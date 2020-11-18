from dataclasses import dataclass, field
from typing import List
import envparse, tempfile, utils

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
        with self._create_temp_dir():
            try:
                self._get_input_paths()
                self._create_pkcs11_provider_config()
                self._login_tpp()
                self._invoke_jar_singer()
            finally:
                self._logout_tpp()
                self._delete_pkcs11_provider_config_path_or_report_error()

    def _create_temp_dir(self):
        return tempfile.TemporaryDirectory()

    def _get_input_paths(self):
        if self.config.input_path is not None:
            self.input_paths = [self.config.input_path]
        else:
            self.input_paths = glob.glob(self.config.input_glob)
