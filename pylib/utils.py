import envparse, os, sys, textwrap, json, pathlib
if os.name == 'nt':
    import winreg

def create_dataclass_inputs_from_env(schema):
    env = envparse.Env(**schema)
    result = {}
    for key in schema.keys():
        result[key.lower()] = env(key)
    return result

def is_jre_64_bit():

def read_windows_registry_key(hive, key, subkey):
    with winreg.OpenKey(hive, key, 0, winreg.KEY_READ) as key:
        return winreg.QueryValueEx(subkey)

def detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir):
    if user_provided_venafi_client_tools_dir is not None:
        return user_provided_venafi_client_tools_dir
    elif sys.platform.startswith('darwin'):
        return pathlib.Path('/Library/Venafi/CodeSigning')
    elif os.name == 'nt':
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, "Software\\Venafi\\Platform", 0) as key:
            winreg.QueryValueEx("Client Base Path")
    else:
        return pathlib.Path('/opt/venafi/codesign')

def get_pkcs11_driver_library_path(user_provided_venafi_client_tools_dir):
    tools_dir = detect_venafi_client_tools_dir(user_provided_venafi_client_tools_dir)
    if os.name == 'nt':
        # The Venafi PKCS11 driver is loaded by jarsigner.exe,
        # so the driver's architecture must match jarsigner's architecture.
        return os.path.join(
            tools_dir,
            'PKCS11',
            is_jre_64_bit() ? 'VenafiPKCS11.dll' : 'VenafiPKCS11-x86.dll'
        )
    else:
        return os.path.join(tools_dir, 'lib', 'venafipkcs11.so')

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
