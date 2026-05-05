#!/usr/bin/env python3

import sys
import logging
from pathlib import Path

if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from euvd_python.cli import cli, EUVDCLIApp


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    if len(sys.argv) == 1:
        app = EUVDCLIApp()
        app.run_interactive()
    else:
        cli()


if __name__ == "__main__":
    main()
