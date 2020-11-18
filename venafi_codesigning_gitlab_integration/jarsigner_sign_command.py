from dataclasses import dataclass, field
from typing import List
import envparse, tempfile, secrets
import venafi_codesigning_gitlab_integration.utils

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    CERTIFICATE_LABEL=str,
    INPUT_PATH=dict(cast=str, default=None),
    INPUT_GLOB=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    EXTRA_CLI_ARGS=dict(cast=list, subcast=str, default=()),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
)

@dataclass
class JarsignerSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    certificate_label: str
    input_path: str = None
    input_glob: str = None
    timestamping_servers: List[str] = ()

    extra_cli_args: List[str] = ()
    venafi_client_tools_dir: str = None

    @classmethod
    def from_env(cls):
        return cls(utils.create_dataclass_inputs_from_env(config_schema))

class JarsignerSignCommand:
    def __init__(self, config: JarsignerSignConfig):
        if config.input_path is not None and config.input_glob is not None:
            raise envparse.ConfigurationError(
                "Only one of 'INPUT_PATH' or 'INPUT_GLOB' may be set, but not both")

        self.config = config

    def run(self):
        self._create_temp_dir()
        try:
            self._get_input_paths()
            self._generate_session_id()
            self._create_pkcs11_provider_config()
            self._login_tpp()
            self._invoke_jar_singer()
        finally:
            self._logout_tpp()
            self._delete_pkcs11_provider_config_path_or_report_error()
            self._delete_temp_dir()

    def _create_temp_dir(self):
        self.temp_dir = tempfile.TemporaryDirectory()

    def _delete_temp_dir(self):
        if hasattr(self, 'temp_dir'):
            self.temp_dir.cleanup()

    def _get_input_paths(self):
        if self.config.input_path is not None:
            self.input_paths = [self.config.input_path]
        else:
            self.input_paths = glob.glob(self.config.input_glob)

    def _generate_session_id(self):
        self.session_id = secrets.token_urlsafe(18)

    def _create_pkcs11_provider_config(self):
        utils.create_pkcs11_provider_config(
            self._pkcs11_provider_config_path(),
            self.config.venafi_client_tools_dir)

    def _pkcs11_provider_config_path(self):
        return os.path.join(self.temp_dir.name, 'pkcs11-provider.conf')

    def _login_tpp(self):
        self._invoke_command(
            'Logging into TPP: configuring client: requesting grant from server.',
            'Successfully obtained grant from TPP.',
            'Error requesting grant from TPP',
            'pkcs11config getgrant',
            command=[
                utils.get_pkcs11config_tool_path(self.config.venafi_client_tools_dir),
                'getgrant',
                '--force',
                '--authurl=' + self.config.tpp_auth_url,
                '--hsmurl=' + self.config.tpp_hsm_url,
                '--username=' + self.config.tpp_username,
                '--password',
                self.config.tpp_password,
            ],
            mask=[
                false,
                false,
                false,
                false,
                false,
                false,
                false,
                true
            ],
            envs={
                'LIBHSMINSTANCE': self.session_id
            }
        )

    def _invoke_command(self, pre_message, success_message, error_message, short_cmdline,
            command, masks=None, env=None):
        self.logger.info(pre_message)
        utils.log_subprocess_run(logger, command, masks)
        proc = subprocess.run(command, capture_output=True, text=True, env=env)


def main():
    try:
        config = JarsignerSignConfig.from_env()
        command = JarsignerSignCommand(config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    command.run()

if __name__ == '__main__':
    main()
