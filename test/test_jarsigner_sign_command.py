from venafi_codesigning_gitlab_integration.jarsigner_sign_command import JarsignerSignConfig
from venafi_codesigning_gitlab_integration.jarsigner_sign_command import JarsignerSignCommand
import logging
import subprocess
import re

fake_tpp_config = {
    'tpp_auth_url': 'http://tpp/auth',
    'tpp_hsm_url': 'http://tpp/hsm',
    'tpp_username': 'user',
    'tpp_password': 'pass',
}


def test_successful_signing_session(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='', stderr='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    getgrant_line = (
        r"/pkcs11config getgrant --force --authurl=http://tpp/auth --hsmurl=http://tpp/hsm "
        r"--username=user --password '\*\*\*'$"
    )
    assert re.search(getgrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully obtained grant from TP' in caplog.text

    jarsigner_line = (
        r"jarsigner verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs foo\.jar 'my cert'$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)
    assert "Successfully signed 'foo.jar'" in caplog.text

    revokegrant_line = r"/pkcs11config revokegrant -force -clear$"
    assert re.search(revokegrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully revoked server grant' in caplog.text
