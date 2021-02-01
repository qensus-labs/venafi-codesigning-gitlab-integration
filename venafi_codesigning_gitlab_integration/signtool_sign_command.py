from dataclasses import dataclass
from typing import List
from venafi_codesigning_gitlab_integration import container_init_command
from venafi_codesigning_gitlab_integration import utils
import envparse
import logging
import sys
import base64
import secrets
import random

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=dict(cast=str, default=None),
    TPP_PASSWORD_BASE64=dict(cast=str, default=None),

    INPUT_PATH=str,
    CERTIFICATE_SUBJECT_NAME=dict(cast=str, default=None),
    CERTIFICATE_SHA1=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    SIGNATURE_DIGEST_ALGOS=dict(cast=list, subcast=str, default=('sha256',)),
    APPEND_SIGNATURES=dict(cast=bool, default=False),
    EXTRA_ARGS=dict(cast=list, subcast=str, default=()),
    EXTRA_TRUSTED_TLS_CA_CERTS=dict(cast=str, default=None),
    SIGNTOOL_PATH=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=True),
    MACHINE_CONFIGURATION=dict(cast=bool, default=False),
)


@dataclass(frozen=True)
class SigntoolSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    input_path: str

    tpp_password: str = None
    tpp_password_base64: str = None
    certificate_subject_name: str = None
    certificate_sha1: str = None
    timestamping_servers: List[str] = ()

    signature_digest_algos: List[str] = ('sha256',)
    append_signatures: bool = False
    extra_args: List[str] = ()
    extra_trusted_tls_ca_certs: str = None
    signtool_path: str = None
    venafi_client_tools_dir: str = None
    isolate_sessions: bool = True
    machine_configuration: bool = False

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class SigntoolSignCommand:
    def __init__(self, logger, config: SigntoolSignConfig):
        utils.check_one_of_two_config_options_set(
            'CERTIFICATE_SUBJECT_NAME', config.certificate_subject_name,
            'CERTIFICATE_SHA1', config.certificate_sha1
        )
        utils.check_one_of_two_config_options_set(
            'TPP_PASSWORD', config.tpp_password,
            'TPP_PASSWORD_BASE64', config.tpp_password_base64
        )

        self.logger = logger
        self.config = config

    def run(self):
        self._maybe_add_extra_trusted_tls_ca_certs()
        try:
            self._generate_session_id()
            self._login_tpp()
            self._invoke_csp_config_sync()
            self._invoke_signtool()
        finally:
            self._logout_tpp()

    def _maybe_add_extra_trusted_tls_ca_certs(self):
        if self.config.extra_trusted_tls_ca_certs is not None:
            utils.add_ca_cert_to_truststore(self.logger, self.config.extra_trusted_tls_ca_certs)

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

    def _invoke_signtool(self):
        signtool_path = utils.get_signtool_path(self.config.signtool_path)

        # With VENAFICSPSilent, when an error occurs at the Venafi CSP driver level,
        # that error is printed as part of the console output, instead of shown
        # in a dialog box that requires the user to click OK.
        env = {
            'VENAFICSPSilent': '1',
            **self.session_env
        }

        for i, signature_digest_algo in enumerate(self.config.signature_digest_algos):
            should_append_signature = self.config.append_signatures or i > 0

            command = [
                signtool_path,
                'sign',
                '/v',
                '/fd',
                signature_digest_algo
            ]

            if len(self.config.timestamping_servers) > 0:
                command.append('/tr')
                command.append(random.choice(
                    self.config.timestamping_servers))

                command.append('/td')
                command.append(signature_digest_algo)

            if should_append_signature:
                command.append('/as')

            if self.config.certificate_subject_name is not None:
                command.append('/n')
                command.append(self.config.certificate_subject_name)
            else:
                command.append('/sha1')
                command.append(self.config.certificate_sha1)

            if self.config.machine_configuration:
                command.append('/sm')

            command += self.config.extra_args
            command.append(self.config.input_path)

            utils.invoke_command(
                self.logger,
                f'Signing with signtool: {self.config.input_path}',
                f"Successfully signed '{self.config.input_path}'.",
                f"Error signing '{self.config.input_path}'",
                'signtool',
                print_output_on_success=True,
                command=command,
                env=env)


def main():
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
        config = SigntoolSignConfig.from_env()
        command = SigntoolSignCommand(logging.getLogger(), config)
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
