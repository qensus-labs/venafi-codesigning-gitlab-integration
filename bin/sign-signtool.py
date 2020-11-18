#!/usr/bin/env python3
import os, sys

root_dir = os.path.dirname(os.path.abspath(os.path.dirname(__file__)))
sys.path.insert(0, os.path.join(root_dir, 'pylib'))

import envparse
from signtool_sign_command import SigntoolSignConfig, SigntoolSignCommand

if __name__ == '__main__':
    try:
        config = SigntoolSignConfig.from_env()
        command = SigntoolSignCommand(config)
    except envparse.ConfigurationError as e:
        print(e, file=sys.stderr)
        sys.exit(1)
    command.run()
