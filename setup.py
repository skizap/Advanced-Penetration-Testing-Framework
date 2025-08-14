#!/usr/bin/env python3
"""
Setup script for Advanced Penetration Testing Framework
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
with open(requirements_path) as f:
    requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = ""
if readme_path.exists():
    with open(readme_path, encoding='utf-8') as f:
        long_description = f.read()

setup(
    name="advanced-pentest-framework",
    version="1.0.0",
    description="Advanced Penetration Testing Framework for Security Research",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Security Research Lab",
    author_email="research@securitylab.com",
    url="https://github.com/securitylab/advanced-pentest-framework",
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "pentest=main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    keywords="penetration-testing security vulnerability-assessment",
    project_urls={
        "Bug Reports": "https://github.com/securitylab/advanced-pentest-framework/issues",
        "Source": "https://github.com/securitylab/advanced-pentest-framework",
        "Documentation": "https://github.com/securitylab/advanced-pentest-framework/wiki",
    },
)