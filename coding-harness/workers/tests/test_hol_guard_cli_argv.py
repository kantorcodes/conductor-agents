"""Pin HOL Guard CLI argument boundaries for Conductor's optional Bash gate."""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace

import pytest

from common import coding_agent as coding_agent_module


@pytest.mark.parametrize(
    "command",
    [
        "git status",
        "-n",
        'printf "%s" "a b"',
        "printf 'one\ntwo'",
    ],
)
def test_hol_guard_command_is_one_positional_argv_after_options(monkeypatch, command):
    """Never reinterpret arbitrary tool-command text as a Guard CLI flag."""
    seen = []

    monkeypatch.setattr(coding_agent_module.shutil, "which", lambda _: "/usr/bin/hol-guard")

    def guard_runner(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps(
                {
                    "classification": {"explicitly_benign": True},
                    "minimum_action": "allow",
                }
            ),
        )

    monkeypatch.setattr(coding_agent_module.subprocess, "run", guard_runner)

    decision = asyncio.run(
        coding_agent_module._hol_guard_pretool(
            {"cwd": os.getcwd(), "tool_input": {"command": command}}, None, None
        )
    )

    assert decision == {}
    assert len(seen) == 1
    argv, kwargs = seen[0]
    assert argv == [
        "/usr/bin/hol-guard", "command", "test", "--json", "--", command
    ]
    assert kwargs.get("shell", False) is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 10
    assert kwargs["cwd"] == os.getcwd()
