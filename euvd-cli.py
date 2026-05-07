#!/usr/bin/env python3
import sys
from pathlib import Path

if __name__ == "__main__":
    project_root = Path(__file__).parent
    sys.path.insert(0, str(project_root))
    from euvd_python.main import main

    main()