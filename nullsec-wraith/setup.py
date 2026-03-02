from setuptools import setup, find_packages

setup(
    name="nullsec-wraith-py",
    version="1.0.0",
    description="👻 Ephemeral Port Scanner (Python) — nullsec freakshow suite",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "wraith-py=wraith_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
