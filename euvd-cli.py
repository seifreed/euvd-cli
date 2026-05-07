#!/usr/bin/env python3
import sys
from pathlib import Path

project_root = Path(__file__).parent
# Needed for editable installs and direct execution before pip install;
# console_scripts entry point does not require this.
sys.path.insert(0, str(project_root))

from euvd_python.main import main

if __name__ == "__main__":
    main()