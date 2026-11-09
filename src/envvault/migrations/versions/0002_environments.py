"""Register environments as first-class rows.

Revision ID: 0002
Revises: 0001
Create Date: 2026-11-09
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

import sqlalchemy as sa
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the environments table and backfill it from existing secrets."""
    op.create_table(
        "environments",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=40), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
        sa.UniqueConstraint("project_id", "name"),
    )
    op.create_index("ix_environments_project_id", "environments", ["project_id"])

    connection = op.get_bind()
    rows = connection.execute(
        sa.text(
            "SELECT DISTINCT project_id, environment FROM secrets ORDER BY project_id, environment"
        )
    ).fetchall()
    now = datetime.now(UTC)
    for project_id, environment in rows:
        connection.execute(
            sa.text(
                "INSERT INTO environments (id, project_id, name, created_at) "
                "VALUES (:id, :project_id, :name, :created_at)"
            ),
            {
                "id": str(uuid.uuid4()),
                "project_id": project_id,
                "name": environment,
                "created_at": now,
            },
        )


def downgrade() -> None:
    """Drop the environments registry (secrets are untouched)."""
    op.drop_index("ix_environments_project_id", table_name="environments")
    op.drop_table("environments")
