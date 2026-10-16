"""Shared unit-test helpers. Dummy values only; real generated data is created by
tests/fixtures/generate.py for integration tests and never committed."""

from __future__ import annotations

import re
from itertools import count
from pathlib import Path

import pytest

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "realistic"


def fill_placeholders(text: str) -> str:
    """Replace __GEN_*__ with unique single-line dummy values (no real secrets)."""
    counter = count(1)
    return re.sub(r"__GEN_[A-Z0-9_]+__", lambda m: f"dummy-{next(counter):03d}", text)


@pytest.fixture
def realistic_main() -> str:
    return fill_placeholders((FIXTURES / "main.example.yml").read_text())
