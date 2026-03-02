from setuptools import setup, find_packages

setup(
    name="nullsec-phantom-py",
    version="1.0.0",
    description="👻 phantom-py — Web Shell Detector (Python fallback)",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "phantom-py=phantom_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
