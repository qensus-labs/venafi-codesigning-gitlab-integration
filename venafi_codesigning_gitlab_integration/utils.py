import envparse
import os
import sys
import errno
import textwrap
import json
import pathlib
import subprocess
import shlex
if os.name == 'nt':
    import winreg

support_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'support'))


class AbortException(Exception):
    pass


def create_dataclass_inputs_from_env(schema):
    env = envparse.Env(**schema)
    result = {}
    for key in schema.keys():
        result[key.lower()] = env(key)
    return result


def is_jre_64_bit():
    java_support_dir = os.path.join(support_dir, 'java')
    proc = subprocess.run(
        ['java', '-classpath', java_support_dir, 'IsJre64Bit'],
        capture_output=True, check=True, text=True)
    return proc.stdout.strip() == 'true'


def is_windows_64_bit():
    return os.getenv('ProgramFiles(x86)') is not None


def read_windows_registry_key(hive, key, subkey):
    flags = winreg.KEY_READ
    if is_windows_64_bit():
        flags |= winreg.KEY_WOW64_64KEY
    else:
        flags |= winreg.KEY_WOW64_32KEY
    with winreg.OpenKey(hive, key, 0, flags) as key:
        try:
            return winreg.QueryValueEx(subkey)
        except OSError as e:
            if e.errno == errno.ENOENT:
                return None
            else:
                raise e


def detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir):
    if user_provided_venafi_client_tools_dir is not None:
        return pathlib.Pathlib(user_provided_venafi_client_tools_dir)
    elif sys.platform.startswith('darwin'):
        return pathlib.Path('/Library/Venafi/CodeSigning')
    elif os.name == 'nt':
        result = read_windows_registry_key(
            winreg.HKEY_LOCAL_MACHINE,
            "Software\\Venafi\\Platform",
            'Client Base Path')
        if result is not None:
            return pathlib.Path(result)

        program_files = os.getenv('ProgramFiles')
        if program_files is None:
            program_files = 'C:\\Program Files'
        return pathlib.Path(program_files).joinpath('Venafi CodeSign Protect')
    else:
        return pathlib.Path('/opt/venafi/codesign')


def get_pkcs11config_tool_path(user_provided_venafi_client_tools_dir):
    tools_dir = detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir)
    if os.name == 'nt':
        # The Venafi PKCS11 driver stores credentials in the Windows registry.
        # 32-bit and 64-bit executables have access to different Windows registry hives,
        # so we need to make sure that the architecture of pkcs11config.exe matches that
        # of jarsigner.exe.
        if is_jre_64_bit():
            exe = 'PKCS11Config.exe'
        else:
            exe = 'PKCS11Config-x86.exe'
        return tools_dir.join_path(exe)
    else:
        return tools_dir.joinpath('bin').joinpath('pkcs11config')


def get_pkcs11_driver_library_path(user_provided_venafi_client_tools_dir):
    tools_dir = detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir)
    if os.name == 'nt':
        # The Venafi PKCS11 driver is loaded by jarsigner.exe,
        # so the driver's architecture must match jarsigner's architecture.
        if is_jre_64_bit():
            dll_name = 'VenafiPKCS11.dll'
        else:
            dll_name = 'VenafiPKCS11-x86.dll'
        return tools_dir.joinpath('PKCS11').joinpath(dll_name)
    else:
        return tools_dir.joinpath('lib').joinpath('venafipkcs11.so')


def create_pkcs11_provider_config(path, user_provided_venafi_client_tools_dir):
    libpath = get_pkcs11_driver_library_path(user_provided_venafi_client_tools_dir)
    with open(path, 'w') as f:
        f.write(textwrap.dedent(
            """
            name = VenafiPKCS11
            library = %s
            slot = 0,
            """ % (json.dumps(libpath),)
        ))


def log_subprocess_run(logger, command, masks):
    if masks is None:
        command_to_log = command
    else:
        command_to_log = []
        for i, arg in enumerate(command):
            if masks[i]:
                command_to_log.append(arg)
            else:
                command_to_log.append('***')
    logger.info('Running: ' + shlex.join(command_to_log))
