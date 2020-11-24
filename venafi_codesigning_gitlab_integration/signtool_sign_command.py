from dataclasses import dataclass
from typing import List
from venafi_codesigning_gitlab_integration import utils
import envparse
import tempfile
import logging
import sys
import secrets
import random

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    INPUT=str,
    CERTIFICATE_SUBJECT_NAME=dict(cast=str, default=None),
    CERTIFICATE_SHA1=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    SIGNATURE_DIGEST_ALGOS=dict(cast=list, subcast=str, default=('sha256',)),
    APPEND_SIGNATURES=dict(cast=bool, default=False),
    EXTRA_ARGS=dict(cast=list, subcast=str, default=()),
    SIGNTOOL_PATH=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    MACHINE_CONFIGURATION=dict(cast=bool, default=False),
)


@dataclass(frozen=True)
class SigntoolSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    input: str
    certificate_subject_name: str = None
    certificate_sha1: str = None
    timestamping_servers: List[str] = ()

    signature_digest_algos: List[str] = ('sha256',)
    append_signatures: bool = False
    extra_args: List[str] = ()
    signtool_path: str = None
    venafi_client_tools_dir: str = None
    machine_configuration: bool = False

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class SigntoolSignCommand:
    def __init__(self, logger, config: SigntoolSignConfig):
        if config.certificate_subject_name is not None and \
           config.certificate_sha1 is not None:
            raise envparse.ConfigurationError(
                "Only one of 'CERTIFICATE_SUBJECT_NAME' or "
                "'CERTIFICATE_SHA1' may be set, but not both")
        if config.certificate_subject_name is None and config.certificate_sha1 is None:
            raise envparse.ConfigurationError(
                "One of 'CERTIFICATE_SUBJECT_NAME' or 'CERTIFICATE_SHA1' must be set.")

        self.logger = logger
        self.config = config

    def run(self):
        self._create_temp_dir()
        try:
            self._generate_session_id()
            self._login_tpp()
            self._invoke_csp_config_sync()
            self._invoke_signtool()
        finally:
            self._logout_tpp()
            self._delete_temp_dir()

    def _create_temp_dir(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def _delete_temp_dir(self):
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()

    def _generate_session_id(self):
        self.session_id = secrets.token_urlsafe(18)
        self.logger.info('Session ID: %s' % (self.session_id,))

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
            env={
                'LIBHSMINSTANCE': self.session_id
            }
        )

    def _logout_tpp(self):
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
                env={
                    'LIBHSMINSTANCE': self.session_id
                }
            )
        except utils.AbortException:
            # utils.invoke_command() already logged an error message.
            pass
        except Exception:
            # Don't reraise exception: allow temp_dir to be cleaned up
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
            env={
                'LIBHSMINSTANCE': self.session_id
            }
        )

    def _invoke_signtool(self):
        signtool_path = utils.get_signtool_path(self.config.signtool_path)

        # With VENAFICSPSilent, when an error occurs at the Venafi CSP driver level,
        # that error is printed as part of the console output, instead of shown
        # in a dialog box that requires the user to click OK.
        env = {'VENAFICSPSilent': '1', 'LIBHSMINSTANCE': self.session_id}

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
            command.append(self.config.input)

            utils.invoke_command(
                self.logger,
                'Signing with signtool: %s' % (self.config.input,),
                "Successfully signed '%s'." % (self.config.input,),
                "Error signing '%s'" % (self.config.input,),
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
        command.run()
    except utils.AbortException:
        sys.exit(1)


if __name__ == '__main__':
    main()
