# hARPy

[![](https://img.shields.io/pypi/v/harpy-prjct?label=PyPI)][6]
[![](https://img.shields.io/pypi/pyversions/harpy-prjct?label=Python)][6]
[![](https://img.shields.io/pypi/l/harpy-prjct?label=License)][4]

**hARPy is an active/passive ARP discovery tool. It supports [Python 2][1] (2.7) and [Python 3][1] (3.4 to 3.9) and runs only on GNU/Linux.**

## How It Works

Sends [ARP (Address Resolution Protocol)][2] requests (active mode only) for discovering the link layer addresses and sniffs for ARP replies.

## Features

- Ability to...
    - ...detect suspicious packets during scanning,
    - ...scan active (normal or fast) or passive,
    - ...scan more than one range at the same time,
    - ...filter the results using the given scanning range,
    - ...send packets from a fake IP address,
    - ...show number of hosts and ARP reply/request counts.
- Option to determine...
    - ...the amount of ARP requests to be sent,
    - ...the sleep time between each ARP request.

## Tested OSs

- Kali Linux 2020.4
- Kali Linux 2020.3
- Linux Mint 20 "Ulyana"
- openSUSE Leap 15.2
- Pardus 19.4
- Ubuntu 20.04.1 LTS

## Preparation and Installation

### PyPI

```shell
python3 -m pip install -U pip
python3 -m pip install -U setuptools
python3 -m pip install -U harpy-prjct
```

Note: For Python version 2, change the command "python3" to "python2". But first get the PIP script by doing the following:

```shell
curl https://bootstrap.pypa.io/pip/2.7/get-pip.py -o get-pip.py
python2 get-pip.py
```

### GitHub

```shell
git clone https://github.com/serhatcelik/harpy.git
cd harpy
python3 -m harpy --help
```

## Usage

Use the following command to get [usage][3] help:

```shell
harpy --help
```

## Examples

```
# Active scanning for common IP addresses in fast mode on wlan0
harpy -i wlan0 -f

# Passive scanning
harpy -i wlan0 -p

# Scan a fixed range with a count value of 2
harpy -i wlan0 -r 192.168.0.1/24 -c 2

# Scan some fixed ranges with filtering
harpy -i wlan0 -r 172.16.0.1/16 10.0.0.1/8 -F
```

## Feedback

If you have found a bug or have a suggestion, please consider [creating an issue][5].


[1]: https://www.python.org
[2]: https://en.wikipedia.org/wiki/Address_Resolution_Protocol
[3]: https://github.com/serhatcelik/harpy/wiki#usage
[4]: https://choosealicense.com/licenses/mit/
[5]: https://github.com/serhatcelik/harpy/issues
[6]: https://pypi.org/project/harpy-prjct/
