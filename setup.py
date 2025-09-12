#!/usr/bin/env python3
"""
Setup script for Smart Detection System
"""

from setuptools import setup, find_packages
import os

# Read the README file
def read_readme():
    with open("README.md", "r", encoding="utf-8") as fh:
        return fh.read()

# Read requirements
def read_requirements():
    with open("requirements.txt", "r", encoding="utf-8") as fh:
        return [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="smart-detection-system",
    version="1.0.0",
    author="Smart Detection Team",
    author_email="security@smartdetection.com",
    description="Advanced AI-powered security analysis for emails and URLs",
    long_description=read_readme(),
    long_description_content_type="text/markdown",
    url="https://github.com/smartdetection/smart-detection-system",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8",
    install_requires=read_requirements(),
    extras_require={
        "dev": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "flake8>=3.8",
            "black>=21.0",
            "mypy>=0.800",
        ],
        "test": [
            "pytest>=6.0",
            "pytest-cov>=2.0",
            "coverage>=5.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "smart-detection=app:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.yml", "*.yaml"],
        "templates": ["*.html"],
        "static": ["css/*", "js/*", "images/*"],
    },
    keywords="security, malware, phishing, email, url, detection, machine-learning, ai",
    project_urls={
        "Bug Reports": "https://github.com/smartdetection/smart-detection-system/issues",
        "Source": "https://github.com/smartdetection/smart-detection-system",
        "Documentation": "https://smartdetection.readthedocs.io/",
    },
)
