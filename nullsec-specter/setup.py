from setuptools import setup, find_packages

setup(
    name="nullsec-specter-py",
    version="1.0.0",
    description="👁️ SSH Config & Key Auditor (Python) — nullsec freakshow suite",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "specter-py=specter_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
