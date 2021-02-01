from dataclasses import dataclass
from venafi_codesigning_gitlab_integration import container_init_command
from venafi_codesigning_gitlab_integration import utils
import envparse
import tempfile
import logging
import sys
import os
import base64
import secrets

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=dict(cast=str, default=None),
    TPP_PASSWORD_BASE64=dict(cast=str, default=None),

    INPUT_PATH=str,

    EXTRA_TRUSTED_TLS_CA_CERTS=dict(cast=str, default=None),
    TRUSTED_CHAIN_LABEL=dict(cast=str, default=None),
    SIGNTOOL_PATH=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=True),
    MACHINE_CONFIGURATION=dict(cast=bool, default=False),
)


@dataclass(frozen=True)
class SigntoolVerifyConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    input_path: str

    tpp_password: str = None
    tpp_password_base64: str = None
    extra_trusted_tls_ca_certs: str = None
    trusted_chain_label: str = None
    signtool_path: str = None
    venafi_client_tools_dir: str = None
    isolate_sessions: bool = True
    machine_configuration: bool = False

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class SigntoolVerifyCommand:
    def __init__(self, logger, config: SigntoolVerifyConfig):
        utils.check_one_of_two_config_options_set(
            'TPP_PASSWORD', config.tpp_password,
            'TPP_PASSWORD_BASE64', config.tpp_password_base64
        )

        self.logger = logger
        self.config = config

    def run(self):
        self._maybe_add_extra_trusted_tls_ca_certs()
        self._maybe_create_temp_dir()
        try:
            self._generate_session_id()
            self._login_tpp()
            self._maybe_trust_chain_with_label()
            self._invoke_csp_config_sync()
            self._invoke_signtool_verify()
        finally:
            self._logout_tpp()
            self._delete_temp_dir()

    def _maybe_add_extra_trusted_tls_ca_certs(self):
        if self.config.extra_trusted_tls_ca_certs is not None:
            utils.add_ca_cert_to_truststore(self.logger, self.config.extra_trusted_tls_ca_certs)

    def _maybe_create_temp_dir(self):
        if self.config.trusted_chain_label is not None:
            self.temp_dir = tempfile.TemporaryDirectory()

    def _delete_temp_dir(self):
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()

    def _generate_session_id(self):
        if self.config.isolate_sessions:
            session_id = secrets.token_urlsafe(18)
            self.session_env = {'LIBHSMINSTANCE': session_id}
            self.logger.info(f'Session ID: {session_id}')
        else:
            self.session_env = {}

    def _get_tpp_password(self) -> str:
        if self.config.tpp_password is not None:
            return self.config.tpp_password
        else:
            return str(base64.b64decode(self.config.tpp_password_base64), 'utf-8')

    def _login_tpp(self):
        command = [
            utils.get_cspconfig_tool_path(self.config.venafi_client_tools_dir),
            'getgrant',
            '-force',
            '-authurl:' + self.config.tpp_auth_url,
            '-hsmurl:' + self.config.tpp_hsm_url,
            '-username:' + self.config.tpp_username,
            '-password',
            self._get_tpp_password()
        ]
        masks = [
            False,
            False,
            False,
            False,
            False,
            False,
            False,
            True
        ]
        if self.config.machine_configuration:
            command.append('-machine')
            masks.append(False)

        utils.invoke_command(
            self.logger,
            'Logging into TPP: configuring client: requesting grant from server.',
            'Successfully obtained grant from TPP.',
            'Error requesting grant from TPP',
            'cspconfig getgrant',
            print_output_on_success=False,
            command=command,
            masks=masks,
            env=self.session_env
        )

    def _logout_tpp(self):
        if not self.config.isolate_sessions:
            return

        try:
            command = [
                utils.get_cspconfig_tool_path(
                    self.config.venafi_client_tools_dir),
                'revokegrant',
                '-force',
                '-clear'
            ]
            if self.config.machine_configuration:
                command.append('-machine')

            utils.invoke_command(
                self.logger,
                'Logging out of TPP: revoking server grant.',
                'Successfully revoked server grant.',
                'Error revoking grant from TPP',
                'cspconfig revokegrant',
                print_output_on_success=False,
                command=command,
                env=self.session_env
            )
        except utils.AbortException:
            # utils.invoke_command() already logged an error message.
            pass
        except Exception:
            # Don't reraise exception: preserve original exception in
            # run()'s try block
            logging.exception('Unexpected exception during TPP logout')

    def _maybe_trust_chain_with_label(self):
        if self.config.trusted_chain_label is None:
            return

        trusted_chain_path = os.path.join(self.temp_dir.name, 'chain.crt')
        command = [
            'cspconfig',
            'getcert',
            '-label',
            self.config.trusted_chain_label,
            '-chainfile',
            trusted_chain_path
        ]

        utils.invoke_command(
            self.logger,
            f"Fetching trusted chain '{self.config.trusted_chain_label}' from TPP.",
            f"Successfully fetched chain '{self.config.trusted_chain_label}' from TPP.",
            f"Error fetching chain '{self.config.trusted_chain_label}' from TPP",
            'cspconfig getcert',
            print_output_on_success=False,
            command=command,
            env=self.session_env
        )

        utils.add_ca_cert_to_truststore(self.logger, trusted_chain_path)

    def _invoke_csp_config_sync(self):
        command = [
            utils.get_cspconfig_tool_path(
                self.config.venafi_client_tools_dir),
            'sync'
        ]
        if self.config.machine_configuration:
            command.append('-machine')

        utils.invoke_command(
            self.logger,
            'Synchronizing local certificate store with TPP.',
            'Successfully synchronized local certificate store with TPP.',
            'Error synchronizing local certificate store with TPP',
            'cspconfig sync',
            print_output_on_success=False,
            command=command,
            env=self.session_env
        )

    def _invoke_signtool_verify(self):
        signtool_path = utils.get_signtool_path(self.config.signtool_path)

        utils.invoke_command(
            self.logger,
            f'Verifying with signtool: {self.config.input_path}',
            f"Successfully verified '{self.config.input_path}'.",
            f"Error verifying '{self.config.input_path}'",
            'signtool',
            print_output_on_success=True,
            command=[
                signtool_path,
                'verify',
                '/pa',
                self.config.input_path
            ],
            env={
                # With VENAFICSPSilent, when an error occurs at the Venafi CSP driver level,
                # that error is printed as part of the console output, instead of shown
                # in a dialog box that requires the user to click OK.
                'VENAFICSPSilent': '1',
                **self.session_env
            })


def main():
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
        config = SigntoolVerifyConfig.from_env()
        command = SigntoolVerifyCommand(logging.getLogger(), config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    try:
        container_init_command.init_container_environment(logging.getLogger())
        command.run()
    except utils.AbortException:
        sys.exit(1)


if __name__ == '__main__':
    main()
