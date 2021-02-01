from venafi_codesigning_gitlab_integration.signtool_sign_command import SigntoolSignConfig
from venafi_codesigning_gitlab_integration.signtool_sign_command import SigntoolSignCommand
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

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(utils, 'is_windows_64_bit', lambda: True)
    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    getgrant_line = (
        r"/CSPConfig.exe getgrant -force -authurl:http://tpp/auth -hsmurl:http://tpp/hsm "
        r"-username:user -password '\*\*\*'$"
    )
    assert re.search(getgrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully obtained grant from TPP' in caplog.text

    sync_line = (
        r"/CSPConfig.exe sync$"
    )
    assert re.search(sync_line, caplog.text, re.MULTILINE)
    assert 'Successfully synchronized local certificate store with TPP' in caplog.text

    signtool_line = (
        r"signtool sign /v /fd sha256 /n 'my cert' foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)
    assert "Successfully signed 'foo.exe'" in caplog.text

    revokegrant_line = r"/CSPConfig.exe revokegrant -force -clear$"
    assert re.search(revokegrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully revoked server grant' in caplog.text


def test_tpp_login_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
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
    command = SigntoolSignCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert 'Error requesting grant from TPP' in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_tpp_logout_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
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
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    assert 'Error revoking grant from TPP' in caplog.text


def test_signtool_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        if args[0][0] == 'signtool':
            return subprocess.CompletedProcess(
                args=[], returncode=1, stdout='')
        else:
            return subprocess.CompletedProcess(
                args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert "Error signing 'foo.exe': command exited with code 1" in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_sign_with_certificate_sha1(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_sha1='abcd1234',
        input_path='foo.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    signtool_line = (
        r"signtool sign /v /fd sha256 /sha1 abcd1234 foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)
    assert "Successfully signed 'foo.exe'" in caplog.text


def test_timestamping_servers(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        timestamping_servers=['timestamp1.com'],
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    signtool_line = (
        r"signtool sign /v /fd sha256 /tr timestamp1\.com /td sha256 "
        r"/n 'my cert' foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)


def test_append_signature(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        append_signatures=True,
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    signtool_line = (
        r"signtool sign /v /fd sha256 /as /n 'my cert' foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)


def test_multiple_signatures(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        timestamping_servers=['timestamp1.com'],
        signature_digest_algos=['sha1', 'sha256'],
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    assert len(re.findall(r'signtool sign', caplog.text)) == 2

    signtool_line = (
        r"signtool sign /v /fd sha1 /tr timestamp1\.com /td sha1 /n 'my cert' foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)

    signtool_line = (
        r"signtool sign /v /fd sha256 /tr timestamp1\.com /td sha256 /as /n 'my cert' foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)


def test_extra_args(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        extra_args=['/aaaa', '/bbbb'],
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    signtool_line = (
        r"signtool sign /v /fd sha256 /n 'my cert' /aaaa /bbbb foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)


def test_venafi_client_tools_dir(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.jar',
        venafi_client_tools_dir='C:\\Venafi',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(utils, 'is_windows_64_bit', lambda: True)
    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    assert os.path.join('C:\\Venafi', 'CSPConfig.exe') in caplog.text


def test_signtool_path(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolSignConfig(
        certificate_subject_name='my cert',
        input_path='foo.exe',
        signtool_path='C:\\Windows SDK\\bin\\signtool.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolSignCommand(logging.getLogger(), config)
    command.run()

    assert "'C:\\Windows SDK\\bin\\signtool.exe' sign" in caplog.text
