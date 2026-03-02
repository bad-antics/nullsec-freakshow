from setuptools import setup, find_packages

setup(
    name="nullsec-yokai",
    version="1.0.0",
    description="🏮 Cron & Systemd Timer Auditor — nullsec freakshow suite",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "yokai=yokai.cli:main",
        ],
    },
    python_requires=">=3.10",
)
