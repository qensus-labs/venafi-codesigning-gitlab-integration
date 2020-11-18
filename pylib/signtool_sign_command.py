from dataclasses import dataclass
from typing import List
import envparse, tempfile, utils

config_schema = dict(
    TPP_AUTH_URL=str,
    TPP_HSM_URL=str,
    TPP_USERNAME=str,
    TPP_PASSWORD=str,

    INPUT=str,
    CERTIFICATE_SUBJECT_NAME=dict(cast=str, default=None),
    CERTIFICATE_SHA1=dict(cast=str, default=None),
    TIMESTAMPING_SERVERS=dict(cast=list, subcast=str, default=()),

    SIGNATURE_DIGEST_ALGOS=dict(cast=list, subcast=str, default=('sha256')),
    APPEND_SIGNATURES=dict(cast=bool, default=False),
    EXTRA_CLI_ARGS=dict(cast=list, subcast=str, default=()),
    SIGNTOOL_PATH=dict(cast=str, default=None),
    VENAFI_CLIENT_TOOLS_DIR=dict(cast=str, default=None),
    MACHINE_CONFIGURATION=dict(cast=bool, default=False),
)

@dataclass
class JarsignerSignConfig:
    tpp_auth_url: str
    tpp_hsm_url: str
    tpp_username: str
    tpp_password: str

    input: str
    certificate_subject_name: str = None
    certificate_subject_sha1: str = None
    timestamping_servers: List[str] = ()

    signature_digest_algos: List[str] = ('sha256',)
    append_signatures: bool = False
    extra_cli_args: List[str] = ()
    signtool_path: str = None
    venafi_client_tools_dir: str
    machine_configuration: bool = False

    @classmethod
    def from_env(cls):
        return cls(utils.create_dataclass_inputs_from_env(config_schema))

class SigntoolSignCommand:
    def __init__(self, config: SigntoolSignConfig):
        if config.certificate_subject_name is not None and config.certificate_subject_sha1 is not None:
            raise envparse.ConfigurationError(
                "Only one of 'CERTIFICATE_SUBJECT_NAME' or 'CERTIFICATE_SHA1' may be set, but not both")

        self.config = config

    def run(self):
        with self._create_temp_dir():
            try:
                pass
            finally:
                pass

    def _create_temp_dir(self):
        return tempfile.TemporaryDirectory()
