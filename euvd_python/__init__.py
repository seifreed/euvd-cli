from importlib.metadata import PackageNotFoundError, version

# Single source of truth for the version is setup.py (and the wheel/dist
# metadata produced from it). Reading it at runtime via importlib.metadata
# keeps the banner honest about what is actually installed; falls back to
# a sentinel when running from a non-installed checkout.
try:
    __version__ = version("euvd-python-cli")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"
