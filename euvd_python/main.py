#!/usr/bin/env python3
"""
Main entry point for the EUVD Python CLI tool.
"""

import sys
import logging
from pathlib import Path

# Add the package to the path if running directly
if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).parent.parent))

from euvd_python.cli import cli, EUVDCLIApp


def main():
    """Main entry point."""
    # Set up basic logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )

    # If no arguments provided, run interactive mode
    if len(sys.argv) == 1:
        app = EUVDCLIApp()
        app.run_interactive()
    else:
        # Run Click CLI with arguments
        cli()


if __name__ == "__main__":
    main()
