"""Absolute unlock limit: locks after N hours even with continuous use (S4, ADR 0004)."""

from __future__ import annotations

import pytest

from envvault.config import DEFAULT_MAX_UNLOCK_HOURS, Settings
from envvault.runtime import LockedError, Runtime
from envvault.services import vault
from tests.conftest import PASSPHRASE, ApiClient

SECONDS_PER_HOUR = 3600
ONE_MINUTE = 60


class FakeClock:
    """Deterministic monotonic clock."""

    def __init__(self) -> None:
        self.now = 1_000.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture()
def clock(app) -> FakeClock:  # type: ignore[no-untyped-def]
    fake = FakeClock()
    app.state.runtime.clock = fake
    return fake


def _keep_busy(app, settings: Settings, clock: FakeClock, hours: float) -> None:  # type: ignore[no-untyped-def]
    """Simulate an agent calling every minute, so the idle lock never fires."""
    with app.state.session_factory() as db:
        for _ in range(int(hours * SECONDS_PER_HOUR / ONE_MINUTE)):
            clock.advance(ONE_MINUTE)
            vault.enforce_idle(db, settings, app.state.runtime)


def test_default_limit_is_twelve_hours() -> None:
    assert DEFAULT_MAX_UNLOCK_HOURS == 12


def test_busy_vault_locks_after_the_absolute_limit(
    app, vault_ready, settings: Settings, clock: FakeClock
) -> None:
    with app.state.session_factory() as db:
        vault.unlock(db, app.state.runtime, PASSPHRASE, "test")
        db.commit()
    _keep_busy(app, settings, clock, hours=11.9)
    clock.advance(0.2 * SECONDS_PER_HOUR)
    with app.state.session_factory() as db, pytest.raises(LockedError, match="maximum"):
        vault.enforce_idle(db, settings, app.state.runtime)
    assert app.state.runtime.locked()


def test_watchdog_locks_without_any_request(
    app, vault_ready, settings: Settings, clock: FakeClock
) -> None:
    state: Runtime = app.state.runtime
    with app.state.session_factory() as db:
        vault.unlock(db, state, PASSPHRASE, "test")
        db.commit()
        clock.advance(DEFAULT_MAX_UNLOCK_HOURS * SECONDS_PER_HOUR + 1)
        assert vault.enforce_limits(db, settings, state) is True
    assert state.locked()


def test_watchdog_also_applies_the_idle_lock(
    app, vault_ready, settings: Settings, clock: FakeClock
) -> None:
    state: Runtime = app.state.runtime
    with app.state.session_factory() as db:
        vault.unlock(db, state, PASSPHRASE, "test")
        db.commit()
        clock.advance(settings.lock_timeout_minutes * ONE_MINUTE + 1)
        assert vault.enforce_limits(db, settings, state) is True
    assert state.locked()


def test_watchdog_leaves_a_fresh_vault_alone(
    app, vault_ready, settings: Settings, clock: FakeClock
) -> None:
    state: Runtime = app.state.runtime
    with app.state.session_factory() as db:
        vault.unlock(db, state, PASSPHRASE, "test")
        db.commit()
        clock.advance(ONE_MINUTE)
        assert vault.enforce_limits(db, settings, state) is False
    assert not state.locked()


def test_limit_is_configurable_and_audited(auth: ApiClient) -> None:
    current = auth.get("/v1/settings").json()
    assert current["max_unlock_hours"] == DEFAULT_MAX_UNLOCK_HOURS
    response = auth.put(
        "/v1/settings",
        json={"lock_timeout_minutes": current["lock_timeout_minutes"], "max_unlock_hours": 8},
    )
    assert response.status_code == 200, response.text
    assert auth.get("/v1/settings").json()["max_unlock_hours"] == 8
    audit = auth.get("/v1/audit").json()["items"]
    assert any(item["action"] == "settings.update" for item in audit)


def test_limit_out_of_range_is_rejected(auth: ApiClient) -> None:
    response = auth.put("/v1/settings", json={"lock_timeout_minutes": 30, "max_unlock_hours": 0})
    assert response.status_code == 422


def test_daemon_watchdog_tick_locks_an_expired_vault(
    app, vault_ready, settings: Settings, clock: FakeClock
) -> None:
    from envvault.app import watchdog_tick

    state: Runtime = app.state.runtime
    with app.state.session_factory() as db:
        vault.unlock(db, state, PASSPHRASE, "test")
        db.commit()
    clock.advance(DEFAULT_MAX_UNLOCK_HOURS * SECONDS_PER_HOUR + 1)
    watchdog_tick(app)
    assert state.locked()
