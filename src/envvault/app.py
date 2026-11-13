"""FastAPI application factory and process wiring."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from envvault import __version__, migrate
from envvault.api import auth, credentials, exec, projects, secrets, system, tokens
from envvault.config import LOCK_WATCHDOG_SECONDS, Settings
from envvault.crypto import InvalidPassphrase
from envvault.db import build_engine, build_session_factory, secure_database_files
from envvault.runtime import (
    ExecLimitReached,
    LockedError,
    RateLimited,
    Runtime,
    VaultNotInitialized,
)
from envvault.services import vault
from envvault.services.credentials import CredentialCorruption
from envvault.services.envfile import EnvFileTooLarge
from envvault.services.projects import ProjectError
from envvault.services.runner import ExecError
from envvault.services.secrets import SecretCorruption, SecretError
from envvault.services.tokens import AgentForbidden, TokenError

WEB_DIR = Path(__file__).parent / "web"
logger = logging.getLogger("envvault")


def watchdog_tick(app: FastAPI) -> None:
    """Lock the vault if the idle or absolute limit expired (no request needed)."""
    with app.state.session_factory() as db:
        if vault.enforce_limits(db, app.state.settings, app.state.runtime):
            logger.info("vault locked by the watchdog")


async def _watchdog_loop(app: FastAPI) -> None:
    """Run :func:`watchdog_tick` forever, off the event loop."""
    while True:
        await asyncio.sleep(LOCK_WATCHDOG_SECONDS)
        await asyncio.to_thread(watchdog_tick, app)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Apply migrations, open SQLite and tear everything down cleanly."""
    settings: Settings = app.state.settings
    settings.ensure_home()
    migrate.upgrade(settings)
    engine = build_engine(settings.db_path)
    app.state.engine = engine
    app.state.session_factory = build_session_factory(engine)
    app.state.runtime = Runtime(settings)
    secure_database_files(settings.db_path)
    settings.secure_log()
    settings.pid_path.write_text(str(os.getpid()), encoding="utf-8")
    watchdog = asyncio.create_task(_watchdog_loop(app))
    try:
        yield
    finally:
        watchdog.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await watchdog
        app.state.runtime.terminate_all()
        engine.dispose()
        try:
            if settings.pid_path.read_text(encoding="utf-8").strip() == str(os.getpid()):
                settings.pid_path.unlink()
        except FileNotFoundError:
            pass


def create_app(settings: Settings | None = None) -> FastAPI:
    """Build the ASGI app. Pass custom settings in tests."""
    resolved = settings or Settings.from_env()
    app = FastAPI(
        title="EnvVault",
        version=__version__,
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url=None,
        openapi_url="/api/openapi.json",
    )
    app.state.settings = resolved

    @app.middleware("http")
    async def host_guard(request: Request, call_next):  # type: ignore[no-untyped-def]
        """Reject unexpected Host headers to blunt DNS-rebinding attempts."""
        if resolved.enforce_host:
            host = request.headers.get("host", "")
            allowed = {
                resolved.host,
                f"{resolved.host}:{resolved.port}",
                "127.0.0.1",
                f"127.0.0.1:{resolved.port}",
                "localhost",
                f"localhost:{resolved.port}",
                "[::1]",
                f"[::1]:{resolved.port}",
            }
            if host not in allowed:
                return JSONResponse(status_code=400, content={"detail": "host not allowed"})
        return await call_next(request)

    app.include_router(auth.router)
    app.include_router(projects.router)
    app.include_router(credentials.router)
    app.include_router(secrets.router)
    app.include_router(exec.session_router)
    app.include_router(exec.agent_router)
    app.include_router(tokens.router)
    app.include_router(system.router)

    _register_error_handlers(app)

    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        """Serve the single-page dashboard."""
        return FileResponse(
            WEB_DIR / "index.html",
            headers={"Cache-Control": "no-store"},
        )

    @app.get("/favicon.ico", include_in_schema=False)
    def favicon() -> JSONResponse:
        """Avoid noisy 404s from the browser."""
        return JSONResponse(status_code=204, content=None)

    return app


def _register_error_handlers(app: FastAPI) -> None:
    """Translate domain exceptions into safe HTTP responses."""

    @app.exception_handler(LockedError)
    async def _locked(_request: Request, exc: LockedError) -> JSONResponse:
        return JSONResponse(status_code=423, content={"detail": str(exc)})

    @app.exception_handler(VaultNotInitialized)
    async def _not_initialized(_request: Request, exc: VaultNotInitialized) -> JSONResponse:
        return JSONResponse(status_code=409, content={"detail": str(exc)})

    @app.exception_handler(RateLimited)
    async def _rate_limited(_request: Request, exc: RateLimited) -> JSONResponse:
        return JSONResponse(status_code=429, content={"detail": str(exc)})

    @app.exception_handler(ExecLimitReached)
    async def _exec_limit(_request: Request, exc: ExecLimitReached) -> JSONResponse:
        return JSONResponse(status_code=429, content={"detail": str(exc)})

    @app.exception_handler(InvalidPassphrase)
    async def _invalid_passphrase(_request: Request, _exc: InvalidPassphrase) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": "invalid passphrase"})

    @app.exception_handler(AgentForbidden)
    async def _forbidden(_request: Request, exc: AgentForbidden) -> JSONResponse:
        return JSONResponse(status_code=403, content={"detail": str(exc)})

    @app.exception_handler(EnvFileTooLarge)
    async def _too_large(_request: Request, exc: EnvFileTooLarge) -> JSONResponse:
        return JSONResponse(status_code=413, content={"detail": str(exc)})

    @app.exception_handler(SecretCorruption)
    async def _corruption(_request: Request, exc: SecretCorruption) -> JSONResponse:
        logger.exception("secret decryption failure")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(CredentialCorruption)
    async def _credential_corruption(_request: Request, exc: CredentialCorruption) -> JSONResponse:
        logger.exception("credential decryption failure")
        return JSONResponse(status_code=500, content={"detail": str(exc)})

    @app.exception_handler(ProjectError)
    @app.exception_handler(SecretError)
    @app.exception_handler(TokenError)
    @app.exception_handler(ExecError)
    @app.exception_handler(ValueError)
    async def _bad_request(_request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(status_code=400, content={"detail": str(exc)})
