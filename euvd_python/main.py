import logging
import signal
import sys
from typing import Any

from .cli import cli


def _on_sigint(_signum: int, _frame: Any) -> None:
    # Bypass Python's default SIGINT->KeyboardInterrupt translation. Click
    # intercepts KeyboardInterrupt and converts it to Abort/"Aborted!" with
    # exit 1, which hides the canonical 128+SIGINT=130 from the shell.
    # Raising SystemExit here propagates straight through Click's
    # KeyboardInterrupt catch (which only matches KeyboardInterrupt and
    # EOFError) and lets `with` blocks run their __exit__ on the way out.
    raise SystemExit(130)


def _install_signal_handlers() -> None:
    # Restore default SIGPIPE handling so the CLI exits cleanly when its
    # stdout reader closes (e.g. when piped into `head`) instead of raising
    # BrokenPipeError. Guarded for Windows where SIGPIPE does not exist.
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
        # Defensive fallback for non-signal sources (e.g. a thread or test
        # raising KeyboardInterrupt programmatically). Real Ctrl+C now
        # never reaches here because _on_sigint raises SystemExit first.
        sys.exit(130)
