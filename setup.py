# coding=utf-8

"""
Setup script for hARPy.
"""

import io
import setuptools

with io.open("README.md", "r", encoding="utf-8") as readme:
    long_description = readme.read()

setuptools.setup(
    name="harpy-prjct",
    version=__import__("harpy.__license__", fromlist="__license__").VERSION,
    description="Active/passive ARP discovery tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    author="Serhat Çelik",
    url="https://github.com/serhatcelik/harpy",
    download_url="https://github.com/serhatcelik/harpy/releases/latest",
    packages=setuptools.find_packages(),
    classifiers=[
        "Environment :: Console",
        "Intended Audience :: Information Technology",
        "Intended Audience :: Science/Research",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: POSIX",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
    ],
    options={
        "build_scripts": {
            "executable": "/bin/custom_python",
        },
    },
    license="MIT",
    license_files=["LICENSE"],
    keywords=["harpy", "arp", "discovery"],
    platforms=["Linux"],
    package_data={
        "": ["*.conf", "*.json"],
    },
    zip_safe=False,
    entry_points={
        "console_scripts": [
            "harpy = harpy.__main__:setup_py_main",
        ],
    },
    python_requires=">=2.7, !=3.0.*, !=3.1.*, !=3.2.*, !=3.3.*, <4",
    project_urls={
        "Source Code": "https://github.com/serhatcelik/harpy",
        "Bug Tracker": "https://github.com/serhatcelik/harpy/issues",
        "Documentation": "https://github.com/serhatcelik/harpy/wiki",
    },
)
