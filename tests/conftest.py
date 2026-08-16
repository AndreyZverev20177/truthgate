from __future__ import annotations

import pytest

from tools.validators import registry


@pytest.fixture(autouse=True)
def _clean_registry() -> None:
    """Каждый тест начинает с пустым реестром — исключает cross-test-загрязнение."""
    registry.clear()
    yield
    registry.clear()
