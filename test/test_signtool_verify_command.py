from venafi_codesigning_gitlab_integration.signtool_verify_command import SigntoolVerifyConfig
from venafi_codesigning_gitlab_integration.signtool_verify_command import SigntoolVerifyCommand
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


def test_successful_verify_session(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
        input_path='foo.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(utils, 'is_windows_64_bit', lambda: True)
    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolVerifyCommand(logging.getLogger(), config)
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
        r"signtool verify /pa foo\.exe$"
    )
    assert re.search(signtool_line, caplog.text, re.MULTILINE)
    assert "Successfully verified 'foo.exe'" in caplog.text

    revokegrant_line = r"/CSPConfig.exe revokegrant -force -clear$"
    assert re.search(revokegrant_line, caplog.text, re.MULTILINE)
    assert 'Successfully revoked server grant' in caplog.text


def test_tpp_login_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
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
    command = SigntoolVerifyCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert 'Error requesting grant from TPP' in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_tpp_logout_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
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
    command = SigntoolVerifyCommand(logging.getLogger(), config)
    command.run()

    assert 'Error revoking grant from TPP' in caplog.text


def test_unsigned_error(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
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
    command = SigntoolVerifyCommand(logging.getLogger(), config)
    with pytest.raises(utils.AbortException):
        command.run()

    assert "Error verifying 'foo.exe': command exited with code 1" in caplog.text
    assert 'Logging out of TPP' in caplog.text


def test_venafi_client_tools_dir(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
        input_path='foo.jar',
        venafi_client_tools_dir='C:\\Venafi',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(utils, 'is_windows_64_bit', lambda: True)
    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolVerifyCommand(logging.getLogger(), config)
    command.run()

    assert os.path.join('C:\\Venafi', 'CSPConfig.exe') in caplog.text


def test_signtool_path(monkeypatch, caplog):
    caplog.set_level(logging.INFO)

    config = SigntoolVerifyConfig(
        input_path='foo.exe',
        signtool_path='C:\\Windows SDK\\bin\\signtool.exe',
        **fake_tpp_config
    )

    def mock_subprocess_run(*args, **kwargs):
        return subprocess.CompletedProcess(args=[], returncode=0, stdout='')

    monkeypatch.setattr(subprocess, 'run', mock_subprocess_run)
    command = SigntoolVerifyCommand(logging.getLogger(), config)
    command.run()

    assert "'C:\\Windows SDK\\bin\\signtool.exe' verify" in caplog.text
