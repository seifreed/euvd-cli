#!/usr/bin/env python3
"""
Simple runner script for EUVD Python CLI.
"""

import sys
from pathlib import Path

# Add the package to Python path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Import and run
from euvd_python.main import main

if __name__ == "__main__":
    main() 