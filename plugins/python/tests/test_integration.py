"""Integration tests: end-to-end flows against the mock Vanzik server."""

import json

import pytest

from vanzik import Guard, DECISION_ALLOW, DECISION_DENY, DECISION_REQUIRE_APPROVAL
from tests.conftest import MockVanzikHandler


class TestFullCheckAllowFlow:
    def test_full_allow_flow(self, mock_server):
        """Guard.check() -> ALLOW -> all fields populated correctly."""
        MockVanzikHandler.check_response = {
            "decision": "ALLOW",
            "reason": "matches allow:shell:ls",
            "matched_rule": "allow:shell:ls",
        }

        guard = Guard(mock_server, agent_id="integration-agent")
        result = guard.check("shell", command="ls -la /tmp")

        assert result.allowed
        assert not result.denied
        assert not result.needs_approval
        assert result.reason == "matches allow:shell:ls"
        assert result.matched_rule == "allow:shell:ls"

        # Verify the request payload was well-formed
        body = json.loads(MockVanzikHandler.last_request_body)
        assert body["scope"] == "shell"
        assert body["agent_id"] == "integration-agent"
        assert body["command"] == "ls -la /tmp"


class TestFullCheckDenyFlow:
    def test_full_deny_flow(self, mock_server):
        """Guard.check() -> DENY -> fail-closed semantics verified."""
        MockVanzikHandler.check_response = {
            "decision": "DENY",
            "reason": "fork bomb detected",
            "matched_rule": "deny:shell:forkbomb",
        }

        guard = Guard(mock_server, agent_id="test-agent")
        result = guard.check("shell", command=":(){ :|:& };:")

        assert result.denied
        assert not result.allowed
        assert "fork bomb" in result.reason


class TestApproveFlow:
    def test_approve_after_require_approval(self, mock_server):
        """Guard.check() returns REQUIRE_APPROVAL, then Guard.approve() succeeds."""
        MockVanzikHandler.check_response = {
            "decision": "REQUIRE_APPROVAL",
            "reason": "sudo requires approval",
            "approval_id": "ap_test_456",
            "approval_url": f"{mock_server}/v1/approve/ap_test_456",
        }

        guard = Guard(mock_server)
        result = guard.check("shell", command="sudo rm -rf /old")

        assert result.needs_approval
        assert result.approval_id == "ap_test_456"

        # Approve the action
        assert guard.approve("ap_test_456") is True


class TestWaitForApprovalResolved:
    def test_resolved_immediately(self, mock_server):
        """Mock returns resolved status; wait_for_approval should return quickly."""
        MockVanzikHandler.status_response = {
            "id": "ap_789",
            "status": "resolved",
            "decision": "ALLOW",
            "reason": "human approved",
        }

        guard = Guard(mock_server)
        result = guard.wait_for_approval("ap_789", timeout=5, poll_interval=1)

        assert result.allowed
        assert result.reason == "human approved"


class TestWaitForApprovalTimeout:
    def test_timeout_returns_deny(self, mock_server):
        """Mock always returns pending; wait_for_approval should time out and deny."""
        MockVanzikHandler.status_response = {
            "id": "ap_timeout",
            "status": "pending",
        }

        guard = Guard(mock_server)
        result = guard.wait_for_approval("ap_timeout", timeout=2, poll_interval=1)

        assert result.denied
        assert "timed out" in result.reason.lower()
