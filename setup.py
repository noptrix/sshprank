"""Set up sshprank."""
import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(here, "README.md"), encoding="utf-8") as readme:
    long_description = readme.read()


setup(
    name="sshprank",
    version="1.2.3",
    description="SSH mass-scanner, login cracker and banner grabber tool",
    long_description=long_description,
    long_description_content_type='text/markdown',
    url="https://github.com/noptrix/sshprank",
    author="noptrix",
    author_email="noptrix@nullsecurity.net",
    maintainer="Fabian Affolter",
    maintainer_email="fabian@affolter-engineering.ch",
    license="MIT",
    install_requires=["paramiko", "shodan", "python-masscan"],
    packages=find_packages(),
    zip_safe=True,
    include_package_data=True,
    entry_points={"console_scripts": [" sshprank=sshprank:main"]},
    keywords="ssh scanner login cracker",
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: Utilities",
    ],
)
