"""CLI secret commands: link, set, list, remove, reveal, import, export."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from envvault.cli import secrets
from tests.cli_support import PASSPHRASE, Cli

PASS = f"{PASSPHRASE}\n"
VALUE = "s3cr3t-value-XYZ"


@pytest.fixture()
def demo(cli: Cli, tmp_path: Path) -> Cli:
    """CLI with an initialised vault and a ``demo`` project."""
    cli.init()
    cli.add_project("demo", tmp_path / "work")
    return cli


def _set(cli: Cli, key: str = "API_KEY", value: str = VALUE) -> None:
    cli.ok("set", key, "-p", "demo", "-e", "dev", input=f"{PASS}{value}\n")


def test_link_writes_project_file_without_secrets(cli: Cli, tmp_path: Path) -> None:
    cli.ok("link", "-p", "demo", "-e", "prod")
    content = (tmp_path / "work" / ".envvault.toml").read_text(encoding="utf-8")
    assert content == 'project = "demo"\nenvironment = "prod"\n'


def test_link_prompts_for_slug_defaulting_to_directory_name(cli: Cli, tmp_path: Path) -> None:
    cli.ok("link", input="\n")
    content = (tmp_path / "work" / ".envvault.toml").read_text(encoding="utf-8")
    assert 'project = "work"' in content


def test_link_refuses_to_overwrite_without_force(cli: Cli) -> None:
    cli.ok("link", "-p", "demo")
    result = cli("link", "-p", "other")
    assert result.exit_code == 1
    assert "already exists" in result.output
    cli.ok("link", "-p", "other", "--force")


def test_commands_use_linked_project_and_environment(demo: Cli) -> None:
    demo.ok("link", "-p", "demo", "-e", "dev")
    demo.ok("set", "TOKEN", input=f"{PASS}{VALUE}\n")
    assert "TOKEN" in demo.ok("list", input=PASS).output


def test_set_without_project_fails_with_hint(cli: Cli) -> None:
    result = cli("set", "KEY", "-e", "dev")
    assert result.exit_code == 1
    assert "provide --project" in result.output


def test_set_without_environment_fails_with_hint(cli: Cli) -> None:
    result = cli("set", "KEY", "-p", "demo")
    assert result.exit_code == 1
    assert "provide --environment" in result.output


def test_set_reports_created_then_updated(demo: Cli) -> None:
    first = demo.ok("set", "K", "-p", "demo", "-e", "dev", "--value", VALUE, input=PASS)
    second = demo.ok("set", "K", "-p", "demo", "-e", "dev", "--value", "other", input=PASS)
    assert "Secret created" in first.output
    assert "Secret updated" in second.output


def test_set_generate_prints_password_and_stores_it(demo: Cli) -> None:
    result = demo.ok("set", "GEN", "-p", "demo", "-e", "dev", "--generate", "--length", "24", input=PASS)
    assert "Password generated" in result.output
    assert "Secret created" in result.output


def test_set_for_unknown_project_fails(cli: Cli) -> None:
    cli.init()
    result = cli("set", "K", "-p", "ghost", "-e", "dev", "--value", "v", input=PASS)
    assert result.exit_code == 1
    assert "project not found: ghost" in result.output


def test_set_with_wrong_passphrase_fails(demo: Cli) -> None:
    result = demo("set", "K", "-p", "demo", "-e", "dev", "--value", "v", input="wrong-pass-123\n")
    assert result.exit_code == 1
    assert "not authenticated" in result.output


def test_list_shows_names_and_never_the_value(demo: Cli) -> None:
    _set(demo)
    result = demo.ok("list", "-p", "demo", "-e", "dev", input=PASS)
    assert "API_KEY" in result.output
    assert VALUE not in result.output


def test_remove_with_yes_deletes_secret(demo: Cli) -> None:
    _set(demo)
    result = demo.ok("remove", "API_KEY", "-p", "demo", "-e", "dev", "-y", input=PASS)
    assert "Secret removed" in result.output
    assert "API_KEY" not in demo.ok("list", "-p", "demo", "-e", "dev", input=PASS).output


def test_remove_declined_confirmation_exits_nonzero(demo: Cli) -> None:
    _set(demo)
    result = demo("remove", "API_KEY", "-p", "demo", "-e", "dev", input="n\n")
    assert result.exit_code == 1
    assert "API_KEY" in demo.ok("list", "-p", "demo", "-e", "dev", input=PASS).output


def test_reveal_prints_the_value(demo: Cli) -> None:
    _set(demo)
    result = demo.ok("reveal", "API_KEY", "-p", "demo", "-e", "dev", input=PASS)
    assert VALUE in result.output


def test_reveal_copy_sends_value_to_clipboard_without_printing(
    demo: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(demo)
    copied: list[str] = []
    monkeypatch.setattr(secrets, "_copy_to_clipboard", lambda value: copied.append(value) or True)
    result = demo.ok("reveal", "API_KEY", "-p", "demo", "-e", "dev", "--copy", input=PASS)
    assert copied == [VALUE]
    assert VALUE not in result.output
    assert "copied" in result.output


def test_reveal_copy_fails_when_no_clipboard_utility(
    demo: Cli, monkeypatch: pytest.MonkeyPatch
) -> None:
    _set(demo)
    monkeypatch.setattr(secrets, "_copy_to_clipboard", lambda value: False)
    result = demo("reveal", "API_KEY", "-p", "demo", "-e", "dev", "--copy", input=PASS)
    assert result.exit_code == 1
    assert "no clipboard utility" in result.output
    assert VALUE not in result.output


def test_reveal_unknown_key_fails(demo: Cli) -> None:
    result = demo("reveal", "NOPE", "-p", "demo", "-e", "dev", input=PASS)
    assert result.exit_code == 1


def test_import_reads_env_file_and_reports_counts(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text(f"A=1\nB={VALUE}\n", encoding="utf-8")
    result = demo.ok("import", str(env_file), "-p", "demo", "-e", "dev", input=PASS)
    assert "2 created" in result.output
    assert VALUE not in result.output
    assert env_file.exists()
    listed = demo.ok("list", "-p", "demo", "-e", "dev", input=PASS).output
    assert "A" in listed and "B" in listed


def test_import_prints_parse_issues(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=1\nthis is not valid\n", encoding="utf-8")
    result = demo.ok("import", str(env_file), "-p", "demo", "-e", "dev", input=PASS)
    assert "line 2" in result.output


def test_import_skips_existing_keys_unless_replace(demo: Cli, tmp_path: Path) -> None:
    _set(demo, "A", "old")
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=new\n", encoding="utf-8")
    skipped = demo.ok("import", str(env_file), "-p", "demo", "-e", "dev", input=PASS)
    replaced = demo.ok("import", str(env_file), "-p", "demo", "-e", "dev", "--replace", input=PASS)
    assert "1 skipped" in skipped.output
    assert "1 updated" in replaced.output


def test_import_delete_file_with_yes_removes_source(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")
    result = demo.ok(
        "import", str(env_file), "-p", "demo", "-e", "dev", "--delete-file", "-y", input=PASS
    )
    assert "File removed" in result.output
    assert not env_file.exists()


def test_import_delete_file_declined_keeps_source(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")
    demo.ok("import", str(env_file), "-p", "demo", "-e", "dev", "--delete-file", input=f"{PASS}n\n")
    assert env_file.exists()


def test_import_create_registers_missing_project(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")
    result = demo.ok(
        "import", str(env_file), "-p", "fresh", "-e", "dev", "--create",
        "--path", str(tmp_path / "work"), input=PASS,
    )  # fmt: skip
    assert "Project created" in result.output
    assert "fresh" in demo.ok("project", "list", input=PASS).output


def test_import_into_missing_project_without_create_fails(demo: Cli, tmp_path: Path) -> None:
    env_file = tmp_path / "work" / ".env"
    env_file.write_text("A=1\n", encoding="utf-8")
    result = demo("import", str(env_file), "-p", "fresh", "-e", "dev", input=PASS)
    assert result.exit_code == 1
    assert "project not found: fresh" in result.output


def test_import_missing_file_fails(demo: Cli, tmp_path: Path) -> None:
    result = demo("import", str(tmp_path / "nope.env"), "-p", "demo", "-e", "dev")
    assert result.exit_code == 1
    assert "file not found" in result.output


def test_export_to_stdout_prints_values(demo: Cli) -> None:
    _set(demo)
    result = demo.ok("export", "-p", "demo", "-e", "dev", input=PASS)
    assert f"API_KEY={VALUE}" in result.output


def test_export_to_file_uses_mode_0600(demo: Cli, tmp_path: Path) -> None:
    _set(demo)
    out = tmp_path / "out" / "exported.env"
    result = demo.ok("export", "-p", "demo", "-e", "dev", "-o", str(out), input=PASS)
    assert VALUE not in result.output
    assert VALUE in out.read_text(encoding="utf-8")
    assert stat.S_IMODE(out.stat().st_mode) == 0o600


def test_export_refuses_existing_file_without_force(demo: Cli, tmp_path: Path) -> None:
    _set(demo)
    out = tmp_path / "exported.env"
    out.write_text("keep", encoding="utf-8")
    result = demo("export", "-p", "demo", "-e", "dev", "-o", str(out), input=PASS)
    assert result.exit_code == 1
    assert out.read_text(encoding="utf-8") == "keep"
    demo.ok("export", "-p", "demo", "-e", "dev", "-o", str(out), "--force", input=PASS)
    assert VALUE in out.read_text(encoding="utf-8")
