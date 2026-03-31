# Nmapy

> A Python CLI tool that mimics the Nmap network scanning utility.

[![PyPI](https://img.shields.io/pypi/v/nmapy.svg)](https://pypi.org/project/nmapy/)
[![Python](https://img.shields.io/pypi/pyversions/nmapy.svg)](https://pypi.org/project/nmapy/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

## Install

```bash
pip install nmapy
```

## Usage

```python
from nmapy import NmapScan, ScanOptions

options = ScanOptions(
    targets=["192.168.1.1"],
    ports="80,443",
    scan_type="SYN"
)
scan = NmapScan(options)
result = scan.run()
print(result.targets)
print(result.ports)
```

## CLI

```bash
nmapy --help
nmapy -sS -p 80 192.168.1.1
nmapy -v -A scanme.nmapy.org
```

## Development

```bash
git clone https://github.com/daedalus/nmapy.git
cd nmapy
pip install -e ".[test]"

# run tests
pytest

# format
ruff format src/ tests/

# lint
ruff check src/ tests/

# type check
mypy src/
```

## License

MIT License - see LICENSE file for details.