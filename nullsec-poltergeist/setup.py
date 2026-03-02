from setuptools import setup, find_packages

setup(
    name="nullsec-poltergeist-py",
    version="1.0.0",
    description="👻 /proc Anomaly Detector (Python) — nullsec freakshow suite",
    author="bad-antics",
    author_email="nullsec@proton.me",
    license="MIT",
    packages=find_packages(),
    install_requires=["click"],
    entry_points={
        "console_scripts": [
            "poltergeist-py=poltergeist_py.cli:main",
        ],
    },
    python_requires=">=3.10",
)
