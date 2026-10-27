"""encrypt_provider_tokens

Encrypt provider OAuth access/refresh tokens that were stored in plaintext. The column type does
not change (still TEXT); the ORM encrypts on write from now on, and this rewrites existing rows.
Idempotent: values that already carry the encryption prefix are left alone.

Revision ID: e4b7c2a9d1f3
Revises: a7c3e9f1b2d4

"""

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

from app.utils.token_crypto import PREFIX, decrypt_token, encrypt_token

# revision identifiers, used by Alembic.
revision: str = "e4b7c2a9d1f3"
down_revision: Union[str, None] = "a7c3e9f1b2d4"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _rewrite(transform, needs_rewrite) -> None:  # noqa: ANN001
    conn = op.get_bind()
    rows = conn.execute(sa.text("SELECT id, access_token, refresh_token FROM user_connection")).fetchall()
    for row_id, access_token, refresh_token in rows:
        if not (needs_rewrite(access_token) or needs_rewrite(refresh_token)):
            continue
        conn.execute(
            sa.text("UPDATE user_connection SET access_token = :a, refresh_token = :r WHERE id = :id"),
            {"a": transform(access_token), "r": transform(refresh_token), "id": row_id},
        )


def upgrade() -> None:
    _rewrite(encrypt_token, lambda v: v is not None and not v.startswith(PREFIX))


def downgrade() -> None:
    _rewrite(decrypt_token, lambda v: v is not None and v.startswith(PREFIX))
