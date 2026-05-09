from setuptools import setup, find_packages

# Single source of truth; runtime reads back via importlib.metadata.
VERSION = "1.0.1"

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="euvd-python-cli",
    version=VERSION,
    author="Marc Rivero Lopez",
    author_email="mriverolopez@gmail.com",
    description="A Python CLI tool for querying the ENISA EU Vulnerability Database (EUVD) API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/seifreed/euvd-cli",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.13",
    install_requires=requirements,
    extras_require={
        "dev": [
            "bandit==1.9.4",
            "black==26.3.1",
            "mypy==1.20.2",
            "pip-audit",
            "ruff==0.15.12",
            "types-requests==2.33.0.20260503",
        ],
    },
    entry_points={
        "console_scripts": [
            "euvd-cli=euvd_python.main:main",
        ],
    },
    keywords="vulnerability security euvd enisa cli cybersecurity",
    project_urls={
        "Bug Reports": "https://github.com/seifreed/euvd-cli/issues",
        "Source": "https://github.com/seifreed/euvd-cli",
        "Documentation": "https://github.com/seifreed/euvd-cli#readme",
    },
)
