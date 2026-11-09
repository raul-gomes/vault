"""Run the daemon with uvicorn (``envvault serve``)."""

from __future__ import annotations

import logging

import uvicorn

from envvault.config import Settings


def main() -> None:
    """Start the loopback HTTP daemon."""
    settings = Settings.from_env()
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    uvicorn.run(
        "envvault.app:create_app",
        factory=True,
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    main()
