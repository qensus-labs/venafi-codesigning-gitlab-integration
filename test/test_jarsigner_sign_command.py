from venafi_codesigning_gitlab_integration.jarsigner_sign_command import JarsignerSignConfig
from venafi_codesigning_gitlab_integration.jarsigner_sign_command import JarsignerSignCommand
from venafi_codesigning_gitlab_integration import utils
import pytest
import logging
import subprocess
import os
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
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    getgrant_line = (
        r"/pkcs11config getgrant --force --authurl=http://tpp/auth --hsmurl=http://tpp/hsm "
        r"--username=user --password '\*\*\*'$"
    )
    assert re.search(getgrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully obtained grant from TPP' in caplog.text

    jarsigner_line = (
        r"jarsigner -verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs foo\.jar 'my cert'$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)
    assert "Successfully signed 'foo.jar'" in caplog.text

    revokegrant_line = r"/pkcs11config revokegrant -force -clear$"
    assert re.search(revokegrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully revoked server grant' in caplog.text


def test_tpp_login_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getgrant':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert 'Error requesting grant from TPP' in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_tpp_logout_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'revokegrant':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    assert 'Error revoking grant from TPP' in caplog.text


def test_jarsigner_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][0] == 'jarsigner':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert "Error signing 'foo.jar': command exited with code 1" in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_input_glob(monkeypatch, caplog, tmpdir):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_glob=os.path.join(tmpdir, '*.jar'),
        **fake_tpp_config
    )

    a_jar_path = os.path.join(tmpdir, 'a.jar')
    b_jar_path = os.path.join(tmpdir, 'b.jar')
    c_txt_path = os.path.join(tmpdir, 'c.txt')

    open(a_jar_path, 'w').close()
    open(b_jar_path, 'w').close()
    open(c_txt_path, 'w').close()

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    assert len(re.findall(r'jarsigner -verbose', caplog.text)) == 2

    jarsigner_line = (
        r"jarsigner -verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs %s 'my cert'$"
    ) % (a_jar_path,)
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)

    jarsigner_line = (
        r"jarsigner -verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs %s 'my cert'$"
    ) % (b_jar_path,)
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)


def test_timestamping_servers(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        timestamping_servers=['timestamp1.com'],
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    jarsigner_line = (
        r"jarsigner -verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs -tsa timestamp1.com foo\.jar 'my cert'$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)


def test_extra_args(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        extra_args=['-aaaa', '-bbbb'],
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    jarsigner_line = (
        r"jarsigner -verbose -keystore NONE -storetype PKCS11 -storepass none "
        r"-providerclass sun\.security\.pkcs11\.SunPKCS11 -providerArg .*/pkcs11-provider\.conf "
        r"-certs -aaaa -bbbb foo\.jar 'my cert'$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)


def test_venafi_client_tools_dir(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerSignConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        venafi_client_tools_dir='/somewhere/venafi',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerSignCommand(logging.getLogger(), config)
    command.run()

    assert '/somewhere/venafi/bin/pkcs11config' in caplog.text
