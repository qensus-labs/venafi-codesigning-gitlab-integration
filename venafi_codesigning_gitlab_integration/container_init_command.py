# This is the container entrypoint script.
import os
import sys
import logging
import subprocess


def init_container_environment(logger):
    if os.getenv('VENAFI_CONTAINER') != 'true' or \
       os.getenv('VENAFI_CONTAINER_INITIALIZED') == 'true':
        return

    logger.info('Initializing container environment')
    maybe_add_entry_to_hosts_file(logger)
    maybe_register_csp_dll(logger)
    maybe_enable_csp_debugging(logger)
    os.environ['VENAFI_CONTAINER_INITIALIZED'] = 'true'
    logger.info('Container environment initialized')


# Used by Windows tests to add an entry to the hosts file,
# in order to be able to reach our test TPP.
def maybe_add_entry_to_hosts_file(logger):
    entry = os.getenv('VENAFI_CONTAINER_ADD_HOST')
    if entry is None:
        return

    logger.info('Adding %s to hosts file' % (entry,))
    system_root = os.getenv('SystemRoot', 'C:\\Windows')
    hosts_file_path = os.path.join(system_root, 'system32',
                                   'drivers', 'etc', 'hosts')
    with open(hosts_file_path, 'a') as f:
        f.write("\n")
        f.write(entry)
        f.write("\n")


def maybe_register_csp_dll(logger):
    if os.name != 'nt' or os.getenv('VENAFI_CONTAINER_REGISTER_CSP_DLL') != 'true':
        return

    logger.info('Registering Venafi CSP DLL')
    system_root = os.getenv('SystemRoot', 'C:\\Windows')
    subprocess.run(
        ['regsvr32', '/s', os.path.join(system_root, 'system32', 'venaficsp.dll')],
        check=True, )


def maybe_enable_csp_debugging(logger):
    if os.name != 'nt' or os.getenv('VENAFI_CONTAINER_DEBUG_CSP') != 'true':
        return

    logger.info('Enabling Venafi CSP debugging messages')
    subprocess.run(
        ['cspconfig', 'trace', 'console', 'enable', 'out', 'stdout'],
        check=True
    )


def get_default_shell():
    if os.name == 'nt':
        return 'powershell'
    else:
        return 'bash'


def replace_current_process(argv):
    if os.name == 'nt':
        # On Windows, os.execvp() runs the given command in
        # the background while exiting the current one. But we
        # want the caller to wait for the new process too. So
        # here we wait for the new process ourselves.
        try:
            proc = subprocess.run(argv)
            sys.exit(proc.returncode)
        except KeyboardInterrupt:
            sys.exit(1)
    else:
        os.execvp(argv[0], argv)


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)-8s %(message)s')
    init_container_environment(logging.getLogger())
    if len(sys.argv) > 1:
        replace_current_process(sys.argv[1:])
    else:
        replace_current_process([get_default_shell()])


if __name__ == '__main__':
    main()
