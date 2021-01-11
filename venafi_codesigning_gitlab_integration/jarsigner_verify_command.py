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

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    CERTIFICATE_LABEL=str,
    INPUT_PATH=dict(cast=str, default=None),
    INPUT_GLOB=dict(cast=str, default=None),

    EXTRA_TRUSTED_TLS_CA_CERTS=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    ISOLATE_SESSIONS=dict(cast=bool, default=True),
)


@dataclass(frozen=True)
class JarsignerVerifyConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    certificate_label: str
    input_path: str = None
    input_glob: str = None

    extra_trusted_tls_ca_certs: str = None
    venafi_client_tools_dir: str = None
    isolate_sessions: bool = True

    @classmethod
    def from_env(cls):
        return cls(**utils.create_dataclass_inputs_from_env(config_schema))


class JarsignerVerifyCommand:
    def __init__(self, logger, config: JarsignerVerifyConfig):
        if config.input_path is not None and config.input_glob is not None:
            raise envparse.ConfigurationError(
                "Only one of 'INPUT_PATH' or 'INPUT_GLOB' may be set, but not both")
        if config.input_path is None and config.input_glob is None:
            raise envparse.ConfigurationError(
                "One of 'INPUT_PATH' or 'INPUT_GLOB' must be set.")

        self.logger = logger
        self.config = config

    def run(self):
        self._maybe_add_extra_trusted_tls_ca_certs()
        self._create_temp_dir()
        try:
            self._determine_input_paths()
            self._generate_session_id()
            self._login_tpp()
            self._get_certificates()
            self._import_certificates()
            self._invoke_jarsigner_verify()
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

    def _get_cert_file_path(self):
        return os.path.join(self.temp_dir.name, 'cert.crt')

    def _get_chain_file_path(self):
        return os.path.join(self.temp_dir.name, 'chain.crt')

    def _get_keystore_file_path(self):
        return os.path.join(self.temp_dir.name, 'keystore')

    def _generate_session_id(self):
        if self.config.isolate_sessions:
            session_id = secrets.token_urlsafe(18)
            self.session_env = {'LIBHSMINSTANCE': session_id}
            self.logger.info(f'Session ID: {session_id}')
        else:
            self.session_env = {}

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

    def _get_certificates(self):
        utils.invoke_command(
            self.logger,
            'Getting certificate chain from TPP.',
            'Successfully obtained certificate chain from TPP.',
            'Error obtaining certificate chain from TPP',
            'pkcs11config getcertificate',
            print_output_on_success=False,
            command=[
                utils.get_pkcs11config_tool_path(
                    self.config.venafi_client_tools_dir),
                'getcertificate',
                '--label=' + self.config.certificate_label,
                '--file=' + self._get_cert_file_path(),
                '--chainfile=' + self._get_chain_file_path()
            ],
            env=self.session_env
        )

    def _import_certificates(self):
        utils.invoke_command(
            self.logger,
            'Importing main certificate into temporary Java key store.',
            'Successfully imported main certificate into temporary Java key store.',
            'Error importing main certificate into temporary Java key store',
            'keytool -import',
            print_output_on_success=False,
            command=[
                'keytool',
                '-import',
                '-trustcacerts',
                '-file', self._get_cert_file_path(),
                '-alias', self._get_cert_file_path(),
                '-keystore', self._get_keystore_file_path(),
                '--storepass', 'notrelevant',
                '--noprompt'
            ]
        )

        with open(self._get_chain_file_path(), 'r', encoding='UTF-8') as f:
            chain_parts = utils.split_cert_chain(f.read())
        for i, chain_part in enumerate(chain_parts):
            chain_part_file_path = os.path.join(self.temp_dir.name, "chain.%d.crt" % (i,))
            with open(chain_part_file_path, 'w', encoding='UTF-8') as f:
                f.write(chain_part)

            utils.invoke_command(
                self.logger,
                'Importing certificate chain [part %d] into temporary Java key store.' % (i,),
                'Successfully imported certificate chain [part %d] into temporary Java key store.' % (i,),  # noqa:E501
                'Error importing certificate chain [part %d] into temporary Java key store' % (i,),
                'keytool -import',
                print_output_on_success=False,
                command=[
                    'keytool',
                    '-import',
                    '-trustcacerts',
                    '-file', chain_part_file_path,
                    '-alias', chain_part_file_path,
                    '-keystore', self._get_keystore_file_path(),
                    '--storepass', 'notrelevant',
                    '--noprompt'
                ]
            )

    def _invoke_jarsigner_verify(self):
        for input_path in self.input_paths:
            output = utils.invoke_command(
                self.logger,
                'Verifying with jarsigner: %s' % (input_path,),
                None,
                "Error verifying '%s'" % (input_path,),
                'jarsigner -verify',
                print_output_on_success=True,
                command=[
                    'jarsigner',
                    '-verify',
                    '-verbose',
                    '-keystore', self._get_keystore_file_path(),
                    input_path,
                ]
            )

            if 'jar is unsigned' not in output:
                self.logger.info("Successfully verified '%s'." % (input_path,))
            else:
                self.logger.error(
                    "Verification of '%s' failed: file is unsigned" %
                    (input_path,)
                )
                raise utils.AbortException()


def main():
    try:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
        config = JarsignerVerifyConfig.from_env()
        command = JarsignerVerifyCommand(logging.getLogger(), config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    try:
        command.run()
    except utils.AbortException:
        sys.exit(1)


if __name__ == '__main__':
    main()
