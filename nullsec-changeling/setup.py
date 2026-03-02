from setuptools import setup, find_packages

setup(
    name="nullsec-changeling-py",
    version="1.0.0",
    description="🎭 Git Repository Secrets Scanner (Python) — nullsec freakshow suite",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "changeling-py=changeling_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
