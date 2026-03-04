"""
setup.py — Legacy setup for Kryphorix.
Prefer pyproject.toml for modern builds.
"""
from setuptools import setup, find_packages

setup(
    name="kryphorix",
    version="2.0.0",
    author="Ademoh Mustapha Onimisi",
    author_email="",
    description="Elite Cyber Security Assessment Suite",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    url="https://github.com/ademohmustapha/kryphorix",
    packages=find_packages(include=["core*", "modules*", "plugins*"]),
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0,<3.0",
        "rich>=13.7.0,<14.0",
        "reportlab>=4.0.0,<5.0",
        "Pillow>=10.0.0,<12.0",
        "cryptography>=41.0.0,<46.0",
        "beautifulsoup4>=4.12.0,<5.0",
        "colorama>=0.4.6,<1.0",
        "tabulate>=0.9.0,<1.0",
        "dnspython>=2.4.0,<3.0",
        "paramiko>=3.3.0,<4.0",
        "PyYAML>=6.0.0,<7.0",
        "lxml>=4.9.0,<6.0",
        "Jinja2>=3.1.0,<4.0",
    ],
    entry_points={
        "console_scripts": [
            "kryphorix=kryphorix_entry:main",
        ],
    },
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
    ],
    scripts=["kryphorix.py"],
)
