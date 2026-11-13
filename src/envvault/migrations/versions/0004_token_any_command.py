"""Add an explicit any-command flag to agent tokens (ADR 0003).

Revision ID: 0004
Revises: 0003
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Existing tokens start as False: without a command list they stop working."""
    with op.batch_alter_table("api_tokens") as batch:
        batch.add_column(
            sa.Column("any_command", sa.Boolean(), nullable=False, server_default=sa.false())
        )


def downgrade() -> None:
    """Drop the flag."""
    with op.batch_alter_table("api_tokens") as batch:
        batch.drop_column("any_command")
