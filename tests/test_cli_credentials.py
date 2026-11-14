"""CLI service credential commands."""

from __future__ import annotations

from pathlib import Path

import pytest

from envvault.cli import credentials
from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"
PASSWORD = "hunter2-Credential-Pw"


@pytest.fixture()
def demo(cli: Cli, tmp_path: Path) -> Cli:
    """CLI with an initialised vault and a ``demo`` project."""
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    return cli


def _add(cli: Cli, name: str = "Hostinger", *extra: str) -> None:
    cli.ok("credential", "add", name, "--password", PASSWORD, *extra, input=PASS)


def test_add_global_credential_reports_scope_and_hides_password(demo: Cli) -> None:
    result = demo.ok(
        "credential", "add", "Hostinger", "-c", "hosting", "-u", "me@example.com",
        "--url", "https://example.com", "-n", "note", "--password", PASSWORD, input=PASS,
    )  # fmt: skip
    assert "Credential created" in result.output
    assert "global" in result.output
    assert PASSWORD not in result.output


def test_add_prompts_for_password_when_not_given(demo: Cli) -> None:
    demo.ok("credential", "add", "Prompted", input=f"{PASSWORD}\n{PASS}")
    shown = demo.ok("credential", "show", "Prompted", input=PASS)
    assert PASSWORD in shown.output


def test_add_generate_stores_a_password_without_printing_it(demo: Cli) -> None:
    result = demo.ok("credential", "add", "Gen", "--generate", "--length", "24", input=PASS)
    assert "Password generated" in result.output
    shown = demo.ok("credential", "show", "Gen", input=PASS)
    assert "password" in shown.output


def test_add_to_project_scopes_the_credential(demo: Cli) -> None:
    _add(demo, "Scoped", "-p", "demo")
    assert "demo" in demo.ok("credential", "list", "-p", "demo", input=PASS).output


def test_add_to_unknown_project_fails(demo: Cli) -> None:
    result = demo("credential", "add", "X", "--password", "p", "-p", "ghost", input=PASS)
    assert result.exit_code == 1
    assert "project not found: ghost" in result.output


def test_list_never_prints_passwords(demo: Cli) -> None:
    _add(demo)
    result = demo.ok("credential", "list", input=PASS)
    assert "Hostinger" in result.output
    assert PASSWORD not in result.output


def test_list_filters_by_query_category_and_global(demo: Cli) -> None:
    _add(demo, "Hostinger", "-c", "hosting")
    _add(demo, "Mailer", "-c", "email", "-p", "demo")
    by_query = demo.ok("credential", "list", "-q", "Host", input=PASS).output
    by_category = demo.ok("credential", "list", "-c", "email", input=PASS).output
    only_global = demo.ok("credential", "list", "--global", input=PASS).output
    assert "Hostinger" in by_query and "Mailer" not in by_query
    assert "Mailer" in by_category and "Hostinger" not in by_category
    assert "Hostinger" in only_global and "Mailer" not in only_global


def test_list_rejects_project_with_global(demo: Cli) -> None:
    result = demo("credential", "list", "-p", "demo", "--global")
    assert result.exit_code == 1
    assert "not both" in result.output


def test_show_by_name_prints_fields_including_password(demo: Cli) -> None:
    _add(demo, "Hostinger", "-u", "me@example.com")
    result = demo.ok("credential", "show", "Hostinger", input=PASS)
    assert PASSWORD in result.output
    assert "me@example.com" in result.output


def test_show_by_id_works(demo: Cli) -> None:
    result = demo.ok("credential", "add", "ById", "--password", PASSWORD, input=PASS)
    credential_id = result.output.split("id ")[-1].strip()
    shown = demo.ok("credential", "show", credential_id, input=PASS)
    assert PASSWORD in shown.output


def test_show_unknown_credential_fails(demo: Cli) -> None:
    result = demo("credential", "show", "ghost", input=PASS)
    assert result.exit_code == 1
    assert "credential not found: ghost" in result.output


def test_show_with_duplicate_names_asks_for_id(demo: Cli) -> None:
    _add(demo, "Same")
    _add(demo, "Same")
    result = demo("credential", "show", "Same", input=PASS)
    assert result.exit_code == 1
    assert "more than one credential" in result.output


def test_show_copy_uses_clipboard_without_printing(
    demo: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    _add(demo)
    copied: list[str] = []
    monkeypatch.setattr(credentials, "_copy_to_clipboard", lambda v: copied.append(v) or True)
    result = demo.ok("credential", "show", "Hostinger", "--copy", input=PASS)
    assert copied == [PASSWORD]
    assert PASSWORD not in result.output


def test_show_copy_fails_without_clipboard(demo: Cli, monkeypatch: pytest.MonkeyPatch) -> None:
    _add(demo)
    monkeypatch.setattr(credentials, "_copy_to_clipboard", lambda v: False)
    result = demo("credential", "show", "Hostinger", "--copy", input=PASS)
    assert result.exit_code == 1
    assert "no clipboard utility" in result.output


def test_show_copy_fails_when_credential_has_no_password(demo: Cli) -> None:
    demo.ok("credential", "add", "NoPw", "--password", "", input=PASS)
    result = demo("credential", "show", "NoPw", "--copy", input=PASS)
    assert result.exit_code == 1
    assert "no saved password" in result.output


def test_update_changes_only_given_fields(demo: Cli) -> None:
    _add(demo, "Hostinger", "-u", "me@example.com")
    result = demo.ok("credential", "update", "Hostinger", "-c", "dns", "--url", "https://x.io", input=PASS)
    assert "Credential updated" in result.output
    shown = demo.ok("credential", "show", "Hostinger", input=PASS).output
    assert PASSWORD in shown
    assert "me@example.com" in shown
    assert "dns" in shown


def test_update_replaces_password_and_renames(demo: Cli) -> None:
    _add(demo)
    demo.ok("credential", "update", "Hostinger", "--name", "Renamed", "--password", "new-pw-123456", input=PASS)
    shown = demo.ok("credential", "show", "Renamed", input=PASS).output
    assert "new-pw-123456" in shown


def test_update_generate_replaces_password(demo: Cli) -> None:
    _add(demo)
    result = demo.ok("credential", "update", "Hostinger", "--generate", input=PASS)
    assert "New password generated" in result.output
    assert PASSWORD not in demo.ok("credential", "show", "Hostinger", input=PASS).output


def test_update_moves_between_project_and_global_scope(demo: Cli) -> None:
    _add(demo)
    demo.ok("credential", "update", "Hostinger", "-p", "demo", input=PASS)
    assert "Hostinger" in demo.ok("credential", "list", "-p", "demo", input=PASS).output
    demo.ok("credential", "update", "Hostinger", "--global", input=PASS)
    assert "Hostinger" in demo.ok("credential", "list", "--global", input=PASS).output


def test_update_keeps_current_project_scope(demo: Cli) -> None:
    _add(demo, "Hostinger", "-p", "demo")
    demo.ok("credential", "update", "Hostinger", "-n", "changed", input=PASS)
    assert "Hostinger" in demo.ok("credential", "list", "-p", "demo", input=PASS).output


def test_update_rejects_project_with_global(demo: Cli) -> None:
    result = demo("credential", "update", "X", "-p", "demo", "--global")
    assert result.exit_code == 1
    assert "not both" in result.output


def test_remove_with_yes_deletes_credential(demo: Cli) -> None:
    _add(demo)
    result = demo.ok("credential", "remove", "Hostinger", "-y", input=PASS)
    assert "Credential removed" in result.output
    assert "Hostinger" not in demo.ok("credential", "list", input=PASS).output


def test_remove_declined_confirmation_keeps_credential(demo: Cli) -> None:
    _add(demo)
    result = demo("credential", "remove", "Hostinger", input=f"{PASS}n\n")
    assert result.exit_code == 1
    assert "Hostinger" in demo.ok("credential", "list", input=PASS).output
