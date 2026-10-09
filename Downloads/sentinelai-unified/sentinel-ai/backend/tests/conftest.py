"""
Shared pytest fixtures for the Phase 9 AI test suite.

Ensures `app` is importable regardless of where pytest is invoked from,
and clears the prompt cache between tests so prompt-loading tests don't
leak state.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from app.ai.prompt_loader import load_prompt


@pytest.fixture(autouse=True)
def _clear_prompt_cache():
    load_prompt.cache_clear()
    yield
    load_prompt.cache_clear()
