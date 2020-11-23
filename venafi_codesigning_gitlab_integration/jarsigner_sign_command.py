from dataclasses import dataclass
from typing import List
from venafi_codesigning_gitlab_integration import utils
import envparse
import tempfile
import logging
import sys
import os
import glob
import secrets
import random

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    CERTIFICATE_LABEL=str,
    INPUT_PATH=dict(cast=str, default=None),
    INPUT_GLOB=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    EXTRA_ARGS=dict(cast=list, subcast=str, default=()),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
)


@dataclass(frozen=True)
class JarsignerSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    certificate_label: str
    input_path: str = None
    input_glob: str = None
    timestamping_servers: List[str] = ()

    extra_args: List[str] = ()
    venafi_client_tools_dir: str = None

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class JarsignerSignCommand:
    def __init__(self, logger, config: JarsignerSignConfig):
        if config.input_path is not None and config.input_glob is not None:
            raise envparse.ConfigurationError(
                "Only one of 'INPUT_PATH' or 'INPUT_GLOB' may be set, but not both")
        if config.input_path is None and config.input_glob is None:
            raise envparse.ConfigurationError(
                "One of 'INPUT_PATH' or 'INPUT_GLOB' must be set.")

        self.logger = logger
        self.config = config

    def run(self):
        self._create_temp_dir()
        try:
            self._determine_input_paths()
            self._generate_session_id()
            self._create_pkcs11_provider_config()
            self._login_tpp()
            self._invoke_jarsigner()
        finally:
            self._logout_tpp()
            self._delete_temp_dir()

    def _create_temp_dir(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def _delete_temp_dir(self):
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()

    def _determine_input_paths(self) -> List[str]:
        if self.config.input_path is not None:
            self.input_paths = [self.config.input_path]
        else:
            self.input_paths = glob.glob(self.config.input_glob)

    def _generate_session_id(self):
        self.session_id = secrets.token_urlsafe(18)
        self.logger.info('Session ID: %s' % (self.session_id,))

    def _create_pkcs11_provider_config(self):
        utils.create_pkcs11_provider_config(
            self._pkcs11_provider_config_path(),
            self.config.venafi_client_tools_dir)

    def _pkcs11_provider_config_path(self) -> str:
        return os.path.join(self.temp_dir.name, 'pkcs11-provider.conf')

    def _login_tpp(self):
        utils.invoke_command(
            self.logger,
            'Logging into TPP: configuring client: requesting grant from server.',
            'Successfully obtained grant from TPP.',
            'Error requesting grant from TPP',
            'pkcs11config getgrant',
            print_output_on_success=False,
            command=[
                utils.get_pkcs11config_tool_path(
                    self.config.venafi_client_tools_dir),
                'getgrant',
                '--force',
                '--authurl=' + self.config.tpp_auth_url,
                '--hsmurl=' + self.config.tpp_hsm_url,
                '--username=' + self.config.tpp_username,
                '--password',
                self.config.tpp_password
            ],
            masks=[
                False,
                False,
                False,
                False,
                False,
                False,
                False,
                True
            ],
            env={
                'LIBHSMINSTANCE': self.session_id
            }
        )

    def _logout_tpp(self):
        try:
            utils.invoke_command(
                self.logger,
                'Logging out of TPP: revoking server grant.',
                'Successfully revoked server grant.',
                'Error revoking grant from TPP',
                'pkcs11config revokegrant',
                print_output_on_success=False,
                command=[
                    utils.get_pkcs11config_tool_path(
                        self.config.venafi_client_tools_dir),
                    'revokegrant',
                    '-force',
                    '-clear'
                ],
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

    def _invoke_jarsigner(self):
        env = {'LIBHSMINSTANCE': self.session_id}
        for input_path in self.input_paths:
            command = [
                'jarsigner',
                '-verbose',
                '-keystore',
                'NONE',
                '-storetype',
                'PKCS11',
                '-storepass',
                'none',
                '-providerclass',
                'sun.security.pkcs11.SunPKCS11',
                '-providerArg',
                self._pkcs11_provider_config_path(),
                '-certs'
            ]

            if len(self.config.timestamping_servers) > 0:
                command.append('-tsa')
                command.append(random.choice(
                    self.config.timestamping_servers))

            command += self.config.extra_args

            command.append(input_path)
            command.append(self.config.certificate_label)

            utils.invoke_command(
                self.logger,
                'Signing with jarsigner: %s' % (input_path,),
                "Successfully signed '%s'." % (input_path,),
                "Error signing '%s'" % (input_path,),
                'jarsigner',
                print_output_on_success=False,
                command=command,
                env=env
            )


def main():
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
        config = JarsignerSignConfig.from_env()
        command = JarsignerSignCommand(logging.getLogger(), config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    try:
        command.run()
    except utils.AbortException:
        sys.exit(1)


if __name__ == '__main__':
    main()
