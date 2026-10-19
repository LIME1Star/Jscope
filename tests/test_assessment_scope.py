import json
from pathlib import Path

import pytest

from jscope.cli import KNOWN_COMMANDS, build_parser, main
from jscope.workspace.assessment import create_assessment_record, normalize_domain, validate_scope_file
from jscope.workspace.store import WorkspaceError


def test_normalize_domain_accepts_url_and_idna():
    assert normalize_domain("HTTPS://ExAmPle.com/") == "example.com"
    assert normalize_domain("xn--bcher-kva.example") == "xn--bcher-kva.example"


@pytest.mark.parametrize("value", ["", "example.com/path", "user@example.com", "127.0.0.1", "localhost", "-bad.example.com"])
def test_normalize_domain_rejects_ambiguous_inputs(value):
    with pytest.raises(WorkspaceError):
        normalize_domain(value)


def test_scope_file_separates_valid_hosts_from_rejected_entries(tmp_path):
    scope = tmp_path / "scope.txt"
    scope.write_text("# authorized\nexample.com\napi.example.com\nnotexample.com\nhttps://bad.example.com/path\napi.example.com\n")
    result = validate_scope_file(scope, "example.com")
    assert result["approved_hosts"] == ["example.com", "api.example.com"]
    assert [x["line"] for x in result["rejected_entries"]] == [4, 5]
    assert result["valid"] is False
    assert len(result["sha256"]) == 64


def test_assessment_approvals_are_per_run_and_known_is_not_approved():
    run = create_assessment_record("example.com", ["example.com", "api.example.com"])
    assert run["authorization"]["fresh_for_this_run"] is True
    assert run["hosts"]["example.com"]["state"] == "known"
    assert run["hosts"]["api.example.com"]["state"] == "known"
    assert run["authorization"]["approved_hosts"] == []


def test_assessment_rejects_approved_host_not_in_known_list():
    with pytest.raises(WorkspaceError):
        create_assessment_record("example.com", ["example.com"], ["api.example.com"])


def test_new_command_creates_workspace_without_network(tmp_path, capsys):
    assert main(["new", "example.com", "--workspace", str(tmp_path)]) == 0
    meta = json.loads((tmp_path / ".jscope-ws" / "workspace.json").read_text())
    assert meta["schema"] == "jscope-domain-workspace/1"
    assert meta["domain"]["root"] == "example.com"
    assert (tmp_path / ".jscope-ws" / "assessments").is_dir()
    assert "network activity: none" in capsys.readouterr().out


def test_scope_check_command_is_registered_and_validates(tmp_path, capsys):
    scope = tmp_path / "scope.txt"
    scope.write_text("example.com\napi.example.com\n")
    assert main(["scope-check", "example.com", str(scope)]) == 0
    assert json.loads(capsys.readouterr().out)["valid"] is True
    sub_actions = [a for a in build_parser()._subparsers._group_actions if hasattr(a, "choices")]
    assert set(sub_actions[0].choices) == KNOWN_COMMANDS
