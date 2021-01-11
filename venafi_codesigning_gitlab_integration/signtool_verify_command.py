from dataclasses import dataclass
from venafi_codesigning_gitlab_integration import container_init_command
from venafi_codesigning_gitlab_integration import utils
import envparse
import logging
import sys
import secrets

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    INPUT=str,

    SIGNTOOL_PATH=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=False),
    MACHINE_CONFIGURATION=dict(cast=bool, default=False),
)


@dataclass(frozen=True)
class SigntoolVerifyConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    input: str

    signtool_path: str = None
    venafi_client_tools_dir: str = None
    isolate_sessions: bool = False
    machine_configuration: bool = False

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class SigntoolVerifyCommand:
    def __init__(self, logger, config: SigntoolVerifyConfig):
        self.logger = logger
        self.config = config

    def run(self):
        try:
            self._generate_session_id()
            self._login_tpp()
            self._invoke_csp_config_sync()
            self._invoke_signtool_verify()
        finally:
            self._logout_tpp()

    def _generate_session_id(self):
        if self.config.isolate_sessions:
            session_id = secrets.token_urlsafe(18)
            self.session_env = {'LIBHSMINSTANCE': session_id}
            self.logger.info(f'Session ID: {session_id}')
        else:
            self.session_env = {}

    def _login_tpp(self):
        command = [
            utils.get_cspconfig_tool_path(self.config.venafi_client_tools_dir),
            'getgrant',
            '-force',
            '-authurl:' + self.config.tpp_auth_url,
            '-hsmurl:' + self.config.tpp_hsm_url,
            '-username:' + self.config.tpp_username,
            '-password',
            self.config.tpp_password
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

    def _invoke_signtool_verify(self):
        signtool_path = utils.get_signtool_path(self.config.signtool_path)

        utils.invoke_command(
            self.logger,
            'Verifying with signtool: %s' % (self.config.input,),
            "Successfully verified '%s'." % (self.config.input,),
            "Error verifying '%s'" % (self.config.input,),
            'signtool',
            print_output_on_success=True,
            command=[
                signtool_path,
                'verify',
                '/pa',
                self.config.input
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
