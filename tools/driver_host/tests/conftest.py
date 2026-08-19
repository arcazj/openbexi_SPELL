from __future__ import annotations

from pathlib import Path

import pytest

from driver_host.config import JournalConfig
from driver_host.journal import OperationJournal
from driver_host.tests.support import make_config


@pytest.fixture
def host_config():
    return make_config()


@pytest.fixture
def journal(tmp_path: Path, host_config):
    value = OperationJournal(
        tmp_path / "driver.sqlite",
        host_config.driver_host_generation,
        JournalConfig(max_entries=100, max_bytes=1_048_576),
    )
    try:
        yield value
    finally:
        value.close()
