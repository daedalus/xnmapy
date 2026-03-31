import pytest


@pytest.fixture
def sample_targets() -> list[str]:
    return ["192.168.1.1", "10.0.0.1", "scanme.xnmapy.org"]


@pytest.fixture
def sample_port_specs() -> list[str]:
    return ["22", "80,443", "1-1000", "U:53,T:80,S:22"]
