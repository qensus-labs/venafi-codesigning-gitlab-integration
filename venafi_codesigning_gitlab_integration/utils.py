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


def check_one_of_two_config_options_set(name1, val1, name2, val2):
    if val1 is not None and val2 is not None:
        raise envparse.ConfigurationError(
            f"Only one of '{name1}' or '{name2}' may be set, but not both.")
    if val1 is None and val2 is None:
        raise envparse.ConfigurationError(
            f"One of '{name1}' or '{name2}' must be set.")


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
    try:
        with winreg.OpenKey(hive, key, 0, flags) as key:
            return winreg.QueryValueEx(key, subkey)[0]
    except FileNotFoundError:
        return None
    except OSError as e:
        if e.errno == errno.ENOENT:
            return None
        else:
            raise e


def detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir):
    if user_provided_venafi_client_tools_dir is not None:
        return pathlib.Path(user_provided_venafi_client_tools_dir)
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
    with open(path, 'w', encoding='UTF-8') as f:
        f.write(textwrap.dedent(
            """
            name = VenafiPKCS11
            library = %s
            slot = 0
            """ % (json.dumps(str(libpath)),)
        ).lstrip())


def get_cspconfig_tool_path(user_provided_venafi_client_tools_dir):
    tools_dir = detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir)
    if is_windows_64_bit():
        exe = 'CSPConfig.exe'
    else:
        exe = 'CSPConfig-x86.exe'
    return tools_dir.joinpath(exe)


def get_signtool_path(user_provided_signtool_path):
    if user_provided_signtool_path is not None:
        return user_provided_signtool_path
    else:
        # Assume it's in PATH
        return 'signtool'


def log_subprocess_run(logger, command, masks):
    if masks is None:
        command_to_log = command
    else:
        command_to_log = []
        for i, arg in enumerate(command):
            if masks[i]:
                command_to_log.append('***')
            else:
                command_to_log.append(arg)
    command_to_log = list(map(lambda x: str(x), command_to_log))
    logger.info('Running: ' + shlex.join(command_to_log))


def invoke_command(logger, pre_message, success_message, error_message, short_cmdline,
                   print_output_on_success, command, masks=None, env=None):
    if env is not None:
        env = {**os.environ, **env}
    logger.info(pre_message)
    log_subprocess_run(logger, command, masks)
    proc = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          text=True, env=env)
    if proc.returncode == 0:
        if print_output_on_success:
            logger.info(proc.stdout)
        if success_message is not None:
            logger.info(success_message)
        return proc.stdout
    else:
        logger.info(
            "%s: command exited with code %d. Output from command '%s' is as follows:\n%s",
            error_message, proc.returncode, short_cmdline, proc.stdout)
        raise AbortException()


def add_ca_cert_to_truststore(logger, path):
    logger.info(f'Adding {path} to the system truststore')
    if os.name == 'nt':
        subprocess.run(
            ['certoc', '-addstore', 'root', path],
            check=True
        )
    else:
        subprocess.run(['cp', path, '/etc/pki/ca-trust/source/anchors/'], check=True)
        subprocess.run(['update-ca-trust', 'extract'], check=True)
