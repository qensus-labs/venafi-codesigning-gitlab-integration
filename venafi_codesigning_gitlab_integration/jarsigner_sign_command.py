from dataclasses import dataclass
from typing import List
from venafi_codesigning_gitlab_integration import utils
import envparse
import tempfile
import logging
import sys
import os
import base64
import glob
import secrets
import random

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=dict(cast=str, default=None),
    TPP_PASSWORD_BASE64=dict(cast=str, default=None),

    CERTIFICATE_LABEL=str,
    INPUT_PATH=dict(cast=str, default=None),
    INPUT_GLOB=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    EXTRA_ARGS=dict(cast=list, subcast=str, default=()),
    EXTRA_TRUSTED_TLS_CA_CERTS=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=True),
)


@dataclass(frozen=True)
class JarsignerSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    certificate_label: str

    tpp_password: str = None
    tpp_password_base64: str = None
    input_path: str = None
    input_glob: str = None
    timestamping_servers: List[str] = ()

    extra_args: List[str] = ()
    extra_trusted_tls_ca_certs: str = None
    venafi_client_tools_dir: str = None
    isolate_sessions: bool = True

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class JarsignerSignCommand:
    def __init__(self, logger, config: JarsignerSignConfig):
        utils.check_one_of_two_config_options_set(
            'INPUT_PATH', config.input_path,
            'INPUT_GLOB', config.input_glob
        )
        utils.check_one_of_two_config_options_set(
            'TPP_PASSWORD', config.tpp_password,
            'TPP_PASSWORD_BASE64', config.tpp_password_base64
        )

        self.logger = logger
        self.config = config

    def run(self):
        self._maybe_add_extra_trusted_tls_ca_certs()
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

    def _maybe_add_extra_trusted_tls_ca_certs(self):
        if self.config.extra_trusted_tls_ca_certs is not None:
            utils.add_ca_cert_to_truststore(self.logger, self.config.extra_trusted_tls_ca_certs)

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
        if self.config.isolate_sessions:
            session_id = secrets.token_urlsafe(18)
            self.session_env = {'LIBHSMINSTANCE': session_id}
            self.logger.info(f'Session ID: {session_id}')
        else:
            self.session_env = {}

    def _create_pkcs11_provider_config(self):
        utils.create_pkcs11_provider_config(
            self._pkcs11_provider_config_path(),
            self.config.venafi_client_tools_dir)

    def _pkcs11_provider_config_path(self) -> str:
        return os.path.join(self.temp_dir.name, 'pkcs11-provider.conf')

    def _get_tpp_password(self) -> str:
        if self.config.tpp_password is not None:
            return self.config.tpp_password
        else:
            return str(base64.b64decode(self.config.tpp_password_base64), 'utf-8')

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
                self._get_tpp_password()
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
            env=self.session_env
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
                env=self.session_env
            )
        except utils.AbortException:
            # utils.invoke_command() already logged an error message.
            pass
        except Exception:
            # Don't reraise exception: allow temp_dir to be cleaned up
            logging.exception('Unexpected exception during TPP logout')

    def _invoke_jarsigner(self):
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
                env=self.session_env
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
