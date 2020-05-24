#!/usr/bin/env python3

from setuptools import find_packages
from setuptools import setup

setup(
    name="telescope",
    version="0.1",
    description="Automated reconnaissance tool",
    author="Wes Vleuten",
    url="https://github.com/WesVleuten/telescope",
    packages=find_packages(),
    package_data={},
    entry_points={"console_scripts": ["telescope=telescope:main"]},
    data_files=[],
    install_requires=[],
    dependency_links=[],
)

