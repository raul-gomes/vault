"""Add service credentials, global or per project.

Revision ID: 0003
Revises: 0002
Create Date: 2026-11-09
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the credentials table (project_id null means global)."""
    op.create_table(
        "credentials",
        sa.Column("id", sa.String(length=36), primary_key=True),
        sa.Column("project_id", sa.String(length=36), nullable=True),
        sa.Column("name", sa.String(length=200), nullable=False),
        sa.Column("category", sa.String(length=40), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(["project_id"], ["projects.id"], ondelete="CASCADE"),
    )
    op.create_index("ix_credentials_project_id", "credentials", ["project_id"])
    op.create_index("ix_credentials_name", "credentials", ["name"])
    op.create_index("ix_credentials_category", "credentials", ["category"])


def downgrade() -> None:
    """Drop the credentials table."""
    op.drop_index("ix_credentials_category", table_name="credentials")
    op.drop_index("ix_credentials_name", table_name="credentials")
    op.drop_index("ix_credentials_project_id", table_name="credentials")
    op.drop_table("credentials")
