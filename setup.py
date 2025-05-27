# ================================
# setup.py
# -*- coding: utf-8 -*-
"""
KISA 네트워크 장비 취약점 분석 API 설치 스크립트
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="kisa-network-analyzer",
    version="1.0.0",
    author="KISA Network Security Team",
    author_email="security@example.com",
    description="KISA 가이드 기반 네트워크 장비 보안 취약점 분석 API",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/kisa-network-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking",
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
    extras_require={
        "dev": [
            "pytest>=7.0",
            "pytest-cov>=4.0",
            "black>=23.0",
            "flake8>=6.0",
            "mypy>=1.0",
            "bandit>=1.7"
        ]
    },
    entry_points={
        "console_scripts": [
            "kisa-analyzer=main:main",
        ],
    },
    include_package_data=True,
    package_data={
        "": ["*.md", "*.txt", "*.yml", "*.yaml"],
        "examples": ["*.cfg", "*.conf"],
        "rules": ["*.py"],
    },
    keywords="network security cisco juniper kisa vulnerability analysis",
    project_urls={
        "Bug Reports": "https://github.com/your-org/kisa-network-analyzer/issues",
        "Source": "https://github.com/your-org/kisa-network-analyzer",
        "Documentation": "https://github.com/your-org/kisa-network-analyzer/wiki",
    },
)