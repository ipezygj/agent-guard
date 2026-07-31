"""The package must advertise the version it is, and export what it promises.

Checked because the sibling repos both got this wrong: evalgate's `__version__`
was three releases stale and numguard's two, while this one happened to be
correct. "Happened to be" is the problem — nothing held it there, and nothing
catches the drift by testing behaviour, because every function still works.
"""
import pathlib

import pytest

import agent_guard

try:
    import tomllib
except ModuleNotFoundError:  # py3.10
    tomllib = pytest.importorskip("tomli", reason="needs tomllib (3.11+) or tomli")

PYPROJECT = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_version():
    with PYPROJECT.open("rb") as f:
        return tomllib.load(f)["project"]["version"]


def test_version_matches_pyproject():
    got = getattr(agent_guard, "__version__", None)
    assert got == _declared_version(), (
        f"agent_guard.__version__ is {got!r} but pyproject ships {_declared_version()!r} — "
        "the package is telling users the wrong thing about itself"
    )


def test_all_is_declared_and_non_empty():
    assert getattr(agent_guard, "__all__", None), "agent_guard declares no __all__"


@pytest.mark.parametrize("name", sorted(getattr(agent_guard, "__all__", [])))
def test_every_promised_name_exists(name):
    assert hasattr(agent_guard, name), f"__all__ promises {name}, which the package does not have"
