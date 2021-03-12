from venafi_codesigning_gitlab_integration.jarsigner_verify_command import JarsignerVerifyConfig
from venafi_codesigning_gitlab_integration.jarsigner_verify_command import JarsignerVerifyCommand
from venafi_codesigning_gitlab_integration import utils
import pytest
import logging
import subprocess
import textwrap
import os
import re

fake_tpp_config = {
    'tpp_auth_url': 'http://tpp/auth',
    'tpp_hsm_url': 'http://tpp/hsm',
    'tpp_username': 'user',
    'tpp_password': 'pass',
}


def create_mock_cert_and_chain(cert_arg, chain_arg):
    assert re.match(r'^--file=', cert_arg)
    assert re.match(r'^--chainfile=', chain_arg)
    cert_path = re.sub('.*?=', '', cert_arg)
    chain_path = re.sub('.*?=', '', chain_arg)

    with open(cert_path, 'w') as f:
        f.write(textwrap.dedent(
            """
            -----BEGIN CERTIFICATE-----
            aaa
            -----END CERTIFICATE-----
            """
        ).lstrip())
    with open(chain_path, 'w') as f:
        f.write(textwrap.dedent(
            """
            -----BEGIN CERTIFICATE-----
            bbb
            -----END CERTIFICATE-----
            """
        ).lstrip())


def test_successful_verify_session(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    command.run()

    getgrant_line = (
        r"/pkcs11config getgrant --force --authurl=http://tpp/auth --hsmurl=http://tpp/hsm "
        r"--username=user --password '\*\*\*'$"
    )
    assert re.search(getgrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully obtained grant from TPP' in caplog.text

    jarsigner_line = (
        r"jarsigner -verify -verbose .*? foo\.jar$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)
    assert "Successfully verified 'foo.jar'" in caplog.text

    revokegrant_line = r"/pkcs11config revokegrant -force -clear$"
    assert re.search(revokegrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully revoked server grant' in caplog.text


def test_tpp_login_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
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
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert 'Error requesting grant from TPP' in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_tpp_logout_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')
        elif args[0][1] == 'revokegrant':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    command.run()

    assert 'Error revoking grant from TPP' in caplog.text


def test_jarsigner_exit_code_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')
        elif args[0][0] == 'jarsigner':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert "Error verifying 'foo.jar': command exited with code 1" in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_jarsigner_unsigned_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')
        elif args[0][0] == 'jarsigner':
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='oops, jar is unsigned')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert "Verification of 'foo.jar' failed: file is unsigned" in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_input_glob(monkeypatch, caplog, tmpdir):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
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
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    command.run()

    assert len(re.findall(r'jarsigner -verify', caplog.text)) == 2

    jarsigner_line = (
        r"jarsigner -verify -verbose .*? .*?/a\.jar$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)

    jarsigner_line = (
        r"jarsigner -verify -verbose .*? .*?/b\.jar$"
    )
    assert re.search(jarsigner_line, caplog.text, re.MULTILINE)


def test_venafi_client_tools_dir(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = JarsignerVerifyConfig(
        certificate_label='my cert',
        input_path='foo.jar',
        venafi_client_tools_dir='/somewhere/venafi',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][1] == 'getcertificate':
            cert_arg, chain_arg = (args[0][3], args[0][4])
            create_mock_cert_and_chain(cert_arg, chain_arg)
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = JarsignerVerifyCommand(logging.getLogger(), config)
    command.run()

    assert '/somewhere/venafi/bin/pkcs11config' in caplog.text
