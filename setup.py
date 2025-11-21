#!/usr/bin/env python3
"""
Setup script for Astrava AI Security Scanner
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

# Read requirements
requirements_file = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [
            line.strip() 
            for line in f 
            if line.strip() and not line.startswith('#')
        ]

setup(
    name="Astrava-ai-security-scanner",
    version="1.0.0",
    author="RAM (Ram Prasad Sahoo)",
    author_email="ramprasadsahoo42@gmail.com",
    description="Advanced AI-Powered Web Security Scanner with OWASP Top 10 Coverage",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/Astrava-security/Astrava-scanner",
    packages=find_packages(),
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
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "Astrava-scanner=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "Astrava_ai_security_scanner": [
            "templates/*",
            "payloads/*",
            "wordlists/*",
        ],
    },
    keywords=[
        "security", "scanner", "vulnerability", "owasp", "ai", "penetration-testing",
        "web-security", "ethical-hacking", "security-assessment", "llama", "ollama"
    ],
    project_urls={
        "Bug Reports": "https://github.com/Astrava-security/Astrava-scanner/issues",
        "Source": "https://github.com/Astrava-security/Astrava-scanner",
        "Documentation": "https://Astrava-scanner.readthedocs.io/",
    },
)
