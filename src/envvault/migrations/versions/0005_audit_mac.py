"""Record how each audit entry is authenticated (keyed chain, S3).

Revision ID: 0005
Revises: 0004
Create Date: 2026-11-13
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Entries written before this revision are plain SHA-256 ('legacy')."""
    with op.batch_alter_table("audit_log") as batch:
        batch.add_column(
            sa.Column("mac", sa.String(length=10), nullable=False, server_default="legacy")
        )


def downgrade() -> None:
    """Drop the column."""
    with op.batch_alter_table("audit_log") as batch:
        batch.drop_column("mac")
