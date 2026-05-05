from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="euvd-python-cli",
    version="1.0.0",
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