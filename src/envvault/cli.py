"""Command-line interface for EnvVault."""

from __future__ import annotations

import contextlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NoReturn

import httpx
import typer
from rich.console import Console
from rich.table import Table

from envvault import __version__
from envvault.config import Settings
from envvault.db import build_engine, build_session_factory, secure_database_files
from envvault.passwords import (
    DEFAULT_LENGTH,
    InvalidLength,
    PasswordOptions,
    entropy_bits,
    generate_password,
)
from envvault.services import vault

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="Cofre local de .env: injeta segredos sem expor os valores ao agente.",
)
project_app = typer.Typer(help="Gerencia projetos registrados.", no_args_is_help=True)
token_app = typer.Typer(help="Gerencia tokens de agente.", no_args_is_help=True)
app.add_typer(project_app, name="project")
app.add_typer(token_app, name="token")

console = Console()
PROJECT_FILE = ".envvault.toml"


class CliError(Exception):
    """Fatal CLI error with a user-facing message."""


@dataclass(slots=True)
class UserSession:
    """Authenticated CLI session; the passphrase stays only in memory."""

    client: httpx.Client
    csrf: str
    passphrase: str

    def request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Send a request with the CSRF header on mutations and raise on error."""
        headers = dict(kwargs.pop("headers", {}))
        if method.upper() not in {"GET", "HEAD", "OPTIONS"}:
            headers["x-csrf-token"] = self.csrf
        response = self.client.request(method, path, headers=headers, **kwargs)
        _raise_for_status(response)
        return response

    def close(self) -> None:
        """Log out server-side (hygiene) and close the HTTP client."""
        with contextlib.suppress(httpx.HTTPError):
            self.client.post("/v1/auth/logout")
        self.client.close()


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #
def _fail(message: str, code: int = 1) -> NoReturn:
    """Print an error and exit non-zero."""
    typer.secho(f"erro: {message}", fg=typer.colors.RED, err=True)
    raise typer.Exit(code)


def _detail(response: httpx.Response) -> str:
    """Extract a safe error message from an API response."""
    try:
        payload = response.json()
    except ValueError:
        return response.text.strip() or response.reason_phrase
    detail = payload.get("detail") if isinstance(payload, dict) else None
    if isinstance(detail, list):
        return "; ".join(str(item.get("msg", item)) for item in detail)
    return str(detail or response.reason_phrase)


def _raise_for_status(response: httpx.Response) -> None:
    """Turn an HTTP error into a :class:`CliError` with context."""
    if response.status_code < 400:
        return
    detail = _detail(response)
    if response.status_code == 401:
        raise CliError(f"não autenticado: {detail}")
    if response.status_code == 423:
        raise CliError("vault bloqueado; rode `envvault unlock` ou informe a passphrase")
    if response.status_code == 409:
        raise CliError(f"{detail}; rode `envvault init`")
    raise CliError(f"HTTP {response.status_code}: {detail}")


def _health(settings: Settings, timeout: float = 1.0) -> dict[str, Any] | None:
    """Return the daemon health payload, or None when it is not reachable."""
    try:
        response = httpx.get(f"{settings.base_url}/v1/health", timeout=timeout)
    except httpx.HTTPError:
        return None
    if response.status_code != 200:
        return None
    payload = response.json()
    return payload if isinstance(payload, dict) else None


def ensure_daemon(settings: Settings) -> None:
    """Start the daemon in the background when it is not already running."""
    if _health(settings) is not None:
        return
    settings.ensure_home()
    log = settings.log_path.open("ab", buffering=0)
    subprocess.Popen(
        [sys.executable, "-m", "envvault.daemon"],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
        env=os.environ.copy(),
    )
    for _ in range(60):
        time.sleep(0.2)
        if _health(settings) is not None:
            return
    _fail(f"o daemon não subiu; veja {settings.log_path}")


def _login(settings: Settings, passphrase: str | None = None) -> UserSession:
    """Unlock the vault and return an in-memory CLI session."""
    ensure_daemon(settings)
    secret = passphrase or typer.prompt("Passphrase", hide_input=True)
    client = httpx.Client(base_url=settings.base_url, timeout=30.0)
    try:
        response = client.post("/v1/auth/login", json={"passphrase": secret})
        _raise_for_status(response)
        csrf = response.json()["csrf_token"]
    except Exception:
        client.close()
        raise
    return UserSession(client=client, csrf=csrf, passphrase=secret)


def _find_project(session: UserSession, slug: str) -> dict[str, Any]:
    """Resolve a project payload by slug."""
    response = session.request("GET", "/v1/projects")
    for item in response.json()["items"]:
        if item["slug"] == slug:
            return item
    raise CliError(f"projeto não encontrado: {slug} (use `envvault project add`)")


def _project_config() -> dict[str, str] | None:
    """Read the nearest ``.envvault.toml`` walking up from the current dir."""
    for directory in [Path.cwd(), *Path.cwd().parents]:
        candidate = directory / PROJECT_FILE
        if candidate.exists():
            data = tomllib.loads(candidate.read_text(encoding="utf-8"))
            config = {}
            if isinstance(data.get("project"), str):
                config["project"] = data["project"]
            if isinstance(data.get("environment"), str):
                config["environment"] = data["environment"]
            return config or None
    return None


def _target(project: str | None, environment: str | None) -> tuple[str, str]:
    """Resolve project/environment from flags, then from .envvault.toml."""
    config = _project_config() or {}
    resolved_project = project or config.get("project")
    resolved_environment = environment or config.get("environment")
    if not resolved_project:
        raise CliError("informe --project (ou crie um .envvault.toml com `envvault link`)")
    if not resolved_environment:
        raise CliError("informe --environment (ou defina environment no .envvault.toml)")
    return resolved_project, resolved_environment


def _table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    """Render a compact table."""
    table = Table(title=title, header_style="bold cyan", title_style="bold")
    for column in columns:
        table.add_column(column, overflow="fold")
    for row in rows:
        table.add_row(*row)
    console.print(table)


def _print_issues(issues: list[dict[str, Any]]) -> None:
    """Print .env parse issues."""
    for issue in issues:
        color = "yellow" if issue.get("level") == "warning" else "red"
        console.print(f"[{color}]linha {issue.get('line')}: {issue.get('message')}[/{color}]")


def _copy_to_clipboard(value: str) -> bool:
    """Copy to the system clipboard when a helper is available."""
    for command in (["wl-copy"], ["xclip", "-selection", "clipboard"], ["pbcopy"]):
        executable = shutil.which(command[0])
        if executable:
            try:
                subprocess.run(
                    [executable, *command[1:]],
                    input=value.encode("utf-8"),
                    check=True,
                    timeout=5,
                )
                return True
            except (subprocess.SubprocessError, OSError):
                continue
    return False


def _stream_exec(client: httpx.Client, path: str, payload: dict[str, Any], csrf: str | None) -> int:
    """Stream SSE events from the daemon and print output as it arrives."""
    headers = {"x-csrf-token": csrf} if csrf else {}
    try:
        with client.stream("POST", path, json=payload, headers=headers) as response:
            if response.status_code >= 400:
                response.read()
                _raise_for_status(response)
            exit_code = 0
            for line in response.iter_lines():
                if not line.startswith("data: "):
                    continue
                event = json.loads(line[6:])
                kind = event.get("type")
                if kind == "output":
                    sys.stdout.write(event.get("text", ""))
                    sys.stdout.flush()
                elif kind == "exit":
                    exit_code = int(event.get("code") or 0)
            return exit_code
    except KeyboardInterrupt:
        return 130


# --------------------------------------------------------------------------- #
# lifecycle
# --------------------------------------------------------------------------- #
@app.command()
def init() -> None:
    """Cria o cofre, pede a passphrase mestra e sobe o daemon."""
    settings = Settings.from_env()
    settings.ensure_home()
    if settings.db_path.exists():
        engine = build_engine(settings.db_path)
        factory = build_session_factory(engine)
        with factory() as db:
            already = vault.is_initialized(db)
        engine.dispose()
        if already:
            _fail(f"já existe um cofre em {settings.db_path}")
    passphrase = typer.prompt("Nova passphrase mestra", hide_input=True, confirmation_prompt=True)
    if len(passphrase) < 10:
        _fail("a passphrase deve ter pelo menos 10 caracteres")
    from envvault import migrate

    migrate.upgrade(settings)
    engine = build_engine(settings.db_path)
    factory = build_session_factory(engine)
    with factory() as db:
        vault.initialize(db, settings, passphrase)
        db.commit()
    engine.dispose()
    secure_database_files(settings.db_path)
    ensure_daemon(settings)
    session = _login(settings, passphrase)
    session.close()
    console.print(f"[bold green]Cofre criado[/bold green] em {settings.home}")
    console.print("[yellow]Não há recuperação de passphrase.[/yellow] Guarde-a com cuidado.")
    console.print(f"Dashboard: [bold]{settings.base_url}[/bold]")
    console.print("Próximo passo: [bold]envvault project add <slug> --path .[/bold]")


@app.command()
def serve() -> None:
    """Roda o daemon em primeiro plano (use o log para depurar)."""
    from envvault.daemon import main as daemon_main

    daemon_main()


@app.command()
def stop() -> None:
    """Para o daemon em segundo plano."""
    settings = Settings.from_env()
    if not settings.pid_path.exists():
        _fail("daemon não está rodando (sem arquivo de PID)")
    try:
        pid = int(settings.pid_path.read_text(encoding="utf-8").strip())
    except ValueError:
        _fail(f"PID inválido em {settings.pid_path}")
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        settings.pid_path.unlink(missing_ok=True)
        console.print("daemon já estava parado")
        return
    for _ in range(50):
        time.sleep(0.1)
        if _health(settings, timeout=0.2) is None:
            settings.pid_path.unlink(missing_ok=True)
            console.print("daemon parado")
            return
    _fail("o daemon não respondeu ao SIGTERM")


@app.command()
def status() -> None:
    """Mostra o estado do daemon e do cofre."""
    settings = Settings.from_env()
    health = _health(settings)
    console.print(f"EnvVault [bold]{__version__}[/bold]")
    console.print(f"home:   {settings.home}")
    console.print(f"banco:  {settings.db_path}")
    if health is None:
        console.print("daemon: [red]não está rodando[/red]")
        return
    state = "desbloqueado" if health.get("unlocked") else "bloqueado"
    color = "green" if health.get("unlocked") else "yellow"
    console.print(f"daemon: [green]ok[/green] em {settings.base_url}")
    console.print(f"cofre:  [{color}]{state}[/{color}]")
    console.print(f"timeout de inatividade: {health.get('lock_timeout_minutes')} min")


@app.command()
def unlock() -> None:
    """Desbloqueia o cofre em memória (a sessão do CLI não é persistida)."""
    settings = Settings.from_env()
    session = _login(settings)
    session.close()
    console.print("[green]Cofre desbloqueado.[/green]")


@app.command()
def lock() -> None:
    """Descarta a chave da memória, encerra sessões e mata comandos em execução."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        session.request("POST", "/v1/auth/lock")
        console.print("[yellow]Cofre bloqueado.[/yellow]")
    finally:
        session.client.close()


# --------------------------------------------------------------------------- #
# projects
# --------------------------------------------------------------------------- #
@project_app.command("add")
def project_add(
    slug: str = typer.Argument(..., help="Identificador curto, ex.: meu-app"),
    name: str | None = typer.Option(None, "--name", "-n", help="Nome exibido"),
    path: str = typer.Option(".", "--path", "-p", help="Diretório do projeto"),
) -> None:
    """Registra um projeto local."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        response = session.request(
            "POST",
            "/v1/projects",
            json={"slug": slug, "name": name or slug, "path": path},
        )
        project = response.json()
        console.print(f"[green]Projeto criado:[/green] {project['slug']} → {project['path']}")
    finally:
        session.close()


@project_app.command("list")
def project_list() -> None:
    """Lista os projetos registrados."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/projects").json()["items"]
        rows = [
            [
                item["slug"],
                item["name"],
                item["path"],
                str(item["secret_count"]),
                ", ".join(env["environment"] for env in item["environments"]) or "—",
            ]
            for item in items
        ]
        _table("Projetos", ["slug", "nome", "path", "segredos", "ambientes"], rows)
    finally:
        session.close()


@project_app.command("remove")
def project_remove(
    slug: str = typer.Argument(...),
    yes: bool = typer.Option(False, "--yes", "-y", help="Não pedir confirmação"),
) -> None:
    """Remove um projeto e todos os seus segredos/tokens."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        project = _find_project(session, slug)
        if not yes and not typer.confirm(
            f"Apagar {slug} e TODOS os segredos/tokens? Esta ação é irreversível"
        ):
            raise typer.Exit(1)
        session.request(
            "DELETE",
            f"/v1/projects/{project['id']}",
            json={"confirm_slug": slug},
        )
        console.print(f"[yellow]Projeto removido:[/yellow] {slug}")
    finally:
        session.close()


@app.command()
def link(
    project: str = typer.Option(..., "--project", "-p", help="Slug do projeto"),
    environment: str = typer.Option("dev", "--environment", "-e", help="Ambiente padrão"),
    force: bool = typer.Option(False, "--force", help="Sobrescrever arquivo existente"),
) -> None:
    """Cria .envvault.toml no diretório atual (sem segredos)."""
    target = Path.cwd() / PROJECT_FILE
    if target.exists() and not force:
        _fail(f"{target} já existe (use --force)")
    target.write_text(
        f'project = "{project}"\nenvironment = "{environment}"\n',
        encoding="utf-8",
    )
    console.print(f"[green]Criado[/green] {target}")


# --------------------------------------------------------------------------- #
# secrets
# --------------------------------------------------------------------------- #
@app.command()
def set(
    key: str = typer.Argument(..., help="Nome da variável, ex.: DATABASE_URL"),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    value: str | None = typer.Option(
        None, "--value", help="Valor literal (evite: fica no histórico do shell)"
    ),
    generate: bool = typer.Option(False, "--generate", help="Gerar uma senha forte"),
    length: int = typer.Option(DEFAULT_LENGTH, "--length", help="Tamanho ao gerar"),
) -> None:
    """Cria ou substitui um segredo (valor pedido oculto por padrão)."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        if generate:
            options = PasswordOptions(length=length)
            secret_value = generate_password(options)
            console.print(
                f"[yellow]Senha gerada ({entropy_bits(options):.0f} bits):[/yellow] "
                f"[bold]{secret_value}[/bold]"
            )
        elif value is not None:
            secret_value = value
        else:
            secret_value = typer.prompt(f"Valor de {key}", hide_input=True)
        item = _find_project(session, slug)
        response = session.request(
            "PUT",
            f"/v1/projects/{item['id']}/secrets",
            json={"environment": env, "key": key, "value": secret_value},
        )
        payload = response.json()
        action = "criado" if payload["created"] else "atualizado"
        console.print(f"[green]Segredo {action}:[/green] {slug}/{env}/{key}")
    finally:
        session.close()


@app.command("list")
def list_secrets(
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
) -> None:
    """Lista nomes e versões dos segredos (nunca os valores)."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        rows_data = session.request(
            "GET",
            f"/v1/projects/{item['id']}/secrets",
            params={"environment": env},
        ).json()["items"]
        rows = [[row["key"], str(row["version"]), str(row["updated_at"])] for row in rows_data]
        _table(f"{slug}/{env}", ["chave", "versão", "atualizado em"], rows)
    finally:
        session.close()


@app.command()
def remove(
    key: str = typer.Argument(...),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Remove um segredo."""
    slug, env = _target(project, environment)
    if not yes and not typer.confirm(f"Remover {key} de {slug}/{env}?"):
        raise typer.Exit(1)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        session.request(
            "DELETE",
            f"/v1/projects/{item['id']}/secrets/{key}",
            params={"environment": env},
        )
        console.print(f"[yellow]Segredo removido:[/yellow] {key}")
    finally:
        session.close()


@app.command()
def reveal(
    key: str = typer.Argument(...),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    copy: bool = typer.Option(False, "--copy", help="Copiar para a área de transferência"),
) -> None:
    """Mostra um valor (auditado) depois de revalidar a passphrase."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        response = session.request(
            "POST",
            f"/v1/projects/{item['id']}/secrets/{key}/reveal",
            json={"environment": env, "passphrase": session.passphrase},
        )
        secret = response.json()["value"]
        if copy:
            if not _copy_to_clipboard(secret):
                _fail("nenhum utilitário de clipboard encontrado (wl-copy/xclip/pbcopy)")
            console.print("[green]Valor copiado para a área de transferência.[/green]")
        else:
            console.print(secret)
    finally:
        session.close()


@app.command("import")
def import_env(
    file: str = typer.Argument(".env", help="Arquivo .env de origem"),
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    replace: bool = typer.Option(False, "--replace", help="Sobrescrever chaves existentes"),
    delete_file: bool = typer.Option(
        False, "--delete-file", help="Apagar o .env após importar (o cofre vira a fonte)"
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Não pedir confirmação ao apagar"),
    create: bool = typer.Option(False, "--create", help="Criar o projeto se não existir"),
    path: str = typer.Option(".", "--path", help="Diretório do projeto ao usar --create"),
) -> None:
    """Importa um .env para o cofre (valida e nunca executa o conteúdo)."""
    source = Path(file).expanduser()
    if not source.is_file():
        _fail(f"arquivo não encontrado: {source}")
    content = source.read_text(encoding="utf-8")
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        try:
            item = _find_project(session, slug)
        except CliError:
            if not create:
                raise
            item = session.request(
                "POST",
                "/v1/projects",
                json={"slug": slug, "name": slug, "path": path},
            ).json()
            console.print(f"[green]Projeto criado:[/green] {slug}")
        response = session.request(
            "POST",
            f"/v1/projects/{item['id']}/import",
            json={"environment": env, "content": content, "replace": replace},
        )
        result = response.json()
        console.print(
            f"[green]Importado[/green] em {slug}/{env}: "
            f"{result['created']} criados, {result['updated']} atualizados, "
            f"{result['skipped']} ignorados"
        )
        _print_issues(result["issues"])
        if delete_file:
            if not yes and not typer.confirm(f"Apagar {source} agora?"):
                return
            source.unlink()
            console.print(f"[yellow]Arquivo removido:[/yellow] {source}")
    finally:
        session.close()


@app.command()
def export(
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    out: str | None = typer.Option(None, "--out", "-o", help="Arquivo de destino"),
    force: bool = typer.Option(False, "--force", help="Sobrescrever destino"),
) -> None:
    """Exporta um ambiente para .env (temporário) ou para stdout."""
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, slug)
        text = session.request(
            "POST",
            f"/v1/projects/{item['id']}/export",
            json={"environment": env, "passphrase": session.passphrase},
        ).text
        if not out:
            sys.stdout.write(text)
            return
        destination = Path(out).expanduser()
        if destination.exists() and not force:
            _fail(f"{destination} já existe (use --force)")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(text, encoding="utf-8")
        destination.chmod(0o600)
        console.print(f"[yellow]Exportado para {destination}[/yellow] (modo 0600)")
        console.print("Apague o arquivo após usar; prefira `envvault run`.")
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# execution
# --------------------------------------------------------------------------- #
def _token_client(settings: Settings, token: str) -> httpx.Client:
    """HTTP client authenticated with an agent token (no cookies)."""
    return httpx.Client(
        base_url=settings.base_url,
        timeout=httpx.Timeout(connect=10, read=None, write=30, pool=10),
        headers={"authorization": f"Bearer {token}"},
    )


@app.command(
    context_settings={"allow_extra_args": True, "ignore_unknown_options": True},
    add_help_option=True,
)
def run(
    ctx: typer.Context,
    project: str | None = typer.Option(None, "--project", "-p"),
    environment: str | None = typer.Option(None, "--environment", "-e"),
    cwd: str | None = typer.Option(None, "--cwd", help="Diretório de execução"),
) -> None:
    """Roda um comando com os segredos injetados pelo daemon.

    Exemplo: envvault run -- npm run dev
    """
    command = list(ctx.args)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        _fail("informe o comando após --, ex.: envvault run -- npm run dev")
    slug, env = _target(project, environment)
    settings = Settings.from_env()
    token = os.environ.get("ENVVAULT_TOKEN")
    if token:
        client = _token_client(settings, token)
        try:
            code = _stream_exec(
                client,
                "/v1/agent/exec",
                {"environment": env, "command": command, "cwd": cwd},
                None,
            )
        finally:
            client.close()
    else:
        session = _login(settings)
        try:
            item = _find_project(session, slug)
            code = _stream_exec(
                session.client,
                "/v1/exec",
                {
                    "project_id": item["id"],
                    "environment": env,
                    "command": command,
                    "cwd": cwd,
                },
                session.csrf,
            )
        finally:
            session.close()
    raise typer.Exit(code)


@app.command()
def context() -> None:
    """Mostra o escopo do token de agente atual (ENVVAULT_TOKEN)."""
    token = os.environ.get("ENVVAULT_TOKEN")
    if not token:
        _fail("ENVVAULT_TOKEN não definido")
    settings = Settings.from_env()
    client = _token_client(settings, token)
    try:
        response = client.get("/v1/agent/context")
        _raise_for_status(response)
        console.print_json(json.dumps(response.json()))
    finally:
        client.close()


# --------------------------------------------------------------------------- #
# tokens
# --------------------------------------------------------------------------- #
@token_app.command("create")
def token_create(
    name: str = typer.Option(..., "--name", "-n", help="Nome do token"),
    project: str = typer.Option(..., "--project", "-p"),
    environment: list[str] = typer.Option(
        ["dev"], "--environment", "-e", help="Ambiente permitido (repetível)"
    ),
    allow: list[str] = typer.Option([], "--allow", help="Prefixo de comando permitido (repetível)"),
    no_list: bool = typer.Option(False, "--no-list", help="Não permitir listar chaves"),
    no_inject: bool = typer.Option(False, "--no-inject", help="Não permitir execução"),
) -> None:
    """Cria um token de agente (o valor aparece uma única vez)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        item = _find_project(session, project)
        response = session.request(
            "POST",
            "/v1/tokens",
            json={
                "name": name,
                "project_id": item["id"],
                "environments": environment,
                "can_list": not no_list,
                "can_inject": not no_inject,
                "allowed_commands": allow,
            },
        )
        raw = response.json()["token"]
        console.print("[bold green]Token criado.[/bold green] Ele não será mostrado novamente:")
        console.print(raw)
        console.print("\nUse no ambiente do agente:")
        console.print(f"  export ENVVAULT_TOKEN={raw}")
        if allow:
            console.print(f"Comandos permitidos: {', '.join(allow)}")
        else:
            console.print(
                "[yellow]Sem restrição de comando; qualquer argv é aceito para este token.[/yellow]"
            )
    finally:
        session.close()


@token_app.command("list")
def token_list() -> None:
    """Lista tokens (sem revelar o valor)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/tokens").json()["items"]
        rows = [
            [
                item["name"],
                item["project"]["slug"],
                ", ".join(item["environments"]),
                ("listar " if item["can_list"] else "")
                + ("executar" if item["can_inject"] else ""),
                item["last_used_at"] or "nunca",
                "ativo" if item["active"] else "revogado",
            ]
            for item in items
        ]
        _table(
            "Tokens",
            ["nome", "projeto", "ambientes", "permissões", "último uso", "status"],
            rows,
        )
    finally:
        session.close()


@token_app.command("revoke")
def token_revoke(
    name: str = typer.Argument(..., help="Nome do token"),
    yes: bool = typer.Option(False, "--yes", "-y"),
) -> None:
    """Revoga um token pelo nome."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        items = session.request("GET", "/v1/tokens").json()["items"]
        matches = [item for item in items if item["name"] == name and item["active"]]
        if not matches:
            _fail(f"token ativo não encontrado: {name}")
        if len(matches) > 1 and not yes:
            _fail("há mais de um token ativo com esse nome; revogue pela interface")
        if not yes and not typer.confirm(f"Revogar o token {name}?"):
            raise typer.Exit(1)
        session.request("DELETE", f"/v1/tokens/{matches[0]['id']}")
        console.print(f"[yellow]Token revogado:[/yellow] {name}")
    finally:
        session.close()


# --------------------------------------------------------------------------- #
# audit / misc
# --------------------------------------------------------------------------- #
@app.command()
def audit(
    limit: int = typer.Option(30, "--limit", "-l", min=1, max=500),
    project: str | None = typer.Option(None, "--project", "-p"),
) -> None:
    """Mostra os últimos eventos de auditoria."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        params: dict[str, Any] = {"limit": limit}
        if project:
            params["project_slug"] = project
        items = session.request("GET", "/v1/audit", params=params).json()["items"]
        rows = [
            [
                item["ts"][:19].replace("T", " "),
                item["actor_type"],
                item["action"],
                item["project_slug"] or "—",
                item["environment"] or "—",
                item["result"],
            ]
            for item in items
        ]
        _table("Auditoria", ["quando", "ator", "ação", "projeto", "ambiente", "resultado"], rows)
    finally:
        session.close()


@app.command()
def verify() -> None:
    """Verifica a integridade da cadeia de auditoria."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        result = session.request("GET", "/v1/audit/verify").json()
        if result["valid"]:
            console.print("[green]Cadeia de auditoria íntegra.[/green]")
        else:
            _fail(f"cadeia quebrada no id {result['first_bad_id']}")
    finally:
        session.close()


@app.command()
def passwd() -> None:
    """Troca a passphrase mestra (re-embrulha a chave de dados)."""
    settings = Settings.from_env()
    session = _login(settings)
    try:
        current = session.passphrase
        new = typer.prompt("Nova passphrase", hide_input=True, confirmation_prompt=True)
        if len(new) < 10:
            _fail("a nova passphrase deve ter pelo menos 10 caracteres")
        session.request(
            "POST",
            "/v1/auth/passphrase",
            json={"current": current, "new": new},
        )
        console.print("[green]Passphrase alterada.[/green]")
    finally:
        session.close()


@app.command()
def generate(
    length: int = typer.Option(DEFAULT_LENGTH, "--length", "-l", min=8, max=256),
    upper: bool = typer.Option(True, "--upper/--no-upper"),
    lower: bool = typer.Option(True, "--lower/--no-lower"),
    digits: bool = typer.Option(True, "--digits/--no-digits"),
    symbols: bool = typer.Option(True, "--symbols/--no-symbols"),
    count: int = typer.Option(1, "--count", "-c", min=1, max=100),
    as_json: bool = typer.Option(False, "--json", help="Saída JSON"),
    copy: bool = typer.Option(False, "--copy", help="Copiar a primeira para o clipboard"),
) -> None:
    """Gera senhas fortes localmente (CSPRNG do sistema)."""
    options = PasswordOptions(
        length=length, upper=upper, lower=lower, digits=digits, symbols=symbols
    )
    try:
        passwords = [generate_password(options) for _ in range(count)]
    except InvalidLength as exc:
        _fail(str(exc))
        return
    bits = round(entropy_bits(options), 1)
    if as_json:
        console.print_json(
            json.dumps(
                {
                    "passwords": passwords,
                    "length": length,
                    "entropy_bits": bits,
                    "alphabet_size": len(options.alphabet()),
                }
            )
        )
        return
    if copy and not _copy_to_clipboard(passwords[0]):
        _fail("nenhum utilitário de clipboard encontrado (wl-copy/xclip/pbcopy)")
    for password in passwords:
        console.print(password)
    console.print(
        f"[dim]{length} caracteres · ~{bits} bits de entropia · "
        f"{len(options.alphabet())} símbolos possíveis[/dim]",
        err=True,
    )


def main() -> None:
    """Console entry point."""
    app()


if __name__ == "__main__":
    main()
