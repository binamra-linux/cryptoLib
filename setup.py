"""
Setup script for SecureCrypto library
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README for long description
readme_file = Path(__file__).parent / "README.md"
long_description = readme_file.read_text(encoding="utf-8") if readme_file.exists() else ""

setup(
    name="secure-crypto",
    version="1.0.1",
    author="Binamra Bikram Pandey",
    author_email="binamrapandey6@gmail.com",
    description="A cryptography library with strong security defaults for non-expert developers",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/binamra-linux/cryptoLib",
    py_modules=["secure_crypto"],
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Security :: Cryptography",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.8",
    install_requires=[
        "cryptography>=42.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "pylint>=2.17.0",
        ],
    },
    keywords="cryptography encryption rsa aes security file-encryption",
    project_urls={
        "Bug Reports": "https://github.com/binamra-linux/cryptoLib/issues",
        "Source": "https://github.com/binamra-linux/cryptoLib",
        "Documentation": "https://github.com/binamra-linux/cryptoLib/blob/main/README.md",
    },
)
