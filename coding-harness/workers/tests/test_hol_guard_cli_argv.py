"""Verify the CLI protocol keeps arbitrary shell commands out of process argv."""

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
        "printf 'one\\ntwo'",
    ],
)
def test_hol_guard_native_hook_receives_command_only_via_stdin(monkeypatch, command):
    """Pass the exact command privately to the native Claude PreToolUse hook."""
    seen = []
    monkeypatch.setattr(coding_agent_module.shutil, "which", lambda _: "/usr/bin/hol-guard")

    def guard_runner(argv, **kwargs):
        seen.append((argv, kwargs))
        return SimpleNamespace(
            returncode=0,
            stdout=json.dumps({
                "policy_action": "allow",
                "reason_code": "native_policy_allow",
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "allow",
                },
            }),
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
    assert argv == ["/usr/bin/hol-guard", "hook", "--harness", "claude-code", "--json"]
    assert command not in argv
    assert json.loads(kwargs["input"]) == {
        "hook_event_name": "PreToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": os.getcwd(),
    }
    assert kwargs.get("shell", False) is False
    assert kwargs["capture_output"] is True
    assert kwargs["text"] is True
    assert kwargs["check"] is False
    assert kwargs["timeout"] == 10
    assert kwargs["cwd"] == os.getcwd()
