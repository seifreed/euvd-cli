import logging
import signal
import sys

from .cli import cli


def main() -> None:
    # Restore default SIGPIPE handling so the CLI exits cleanly when its
    # stdout reader closes (e.g. when piped into `head`) instead of raising
    # BrokenPipeError. Guarded for Windows where SIGPIPE does not exist.
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    try:
        cli()
    except KeyboardInterrupt:
        # Convention: 128 + SIGINT (2) = 130; silent exit, no traceback.
        sys.exit(130)
