from setuptools import setup, find_packages

setup(
    name="nullsec-golem-py",
    version="1.0.0",
    description="🗿 golem-py — Memory-Mapped File Hasher (Python fallback)",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "golem-py=golem_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
