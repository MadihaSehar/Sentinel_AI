"""
Loads specialized analysis prompts (section 27 of the master prompt:
"Do not use one enormous prompt").

Each prompt file is a short, single-purpose instruction that gets paired
with structured evidence at call time by `AIProvider.analyze(prompt,
context)`. Analyzers reference prompts by name (e.g. "sqli_analysis"),
never by file path, so the prompt library can be reorganized without
touching analyzer code.
"""
from __future__ import annotations

import functools
from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent / "prompts"


class PromptNotFoundError(Exception):
    pass


@functools.lru_cache(maxsize=None)
def load_prompt(name: str) -> str:
    """
    Load a prompt by name, e.g. load_prompt("sqli_analysis").
    Cached so repeated analyzer calls don't hit disk every time.
    """
    path = _PROMPTS_DIR / f"{name}.md"
    if not path.exists():
        raise PromptNotFoundError(
            f"No prompt file for '{name}' (looked for {path}). "
            f"Available: {available_prompts()}"
        )
    return path.read_text(encoding="utf-8").strip()


def available_prompts() -> list[str]:
    return sorted(p.stem for p in _PROMPTS_DIR.glob("*.md"))
