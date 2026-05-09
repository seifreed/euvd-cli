import logging
import signal
import sys
from typing import Any

from .cli import cli


def _on_sigint(_signum: int, _frame: Any) -> None:
    # SystemExit bypasses Click's KeyboardInterrupt catch (would print "Aborted!" exit 1).
    raise SystemExit(130)


def _install_signal_handlers() -> None:
    if hasattr(signal, "SIGPIPE"):
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    if hasattr(signal, "SIGINT"):
        signal.signal(signal.SIGINT, _on_sigint)


def main() -> None:
    _install_signal_handlers()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    )
    try:
        cli()
    except KeyboardInterrupt:
        sys.exit(130)
