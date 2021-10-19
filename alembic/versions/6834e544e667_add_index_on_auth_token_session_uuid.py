"""add index on auth_token session_uuid

Revision ID: 6834e544e667
Revises: 6ab0ef651dcd

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = '6834e544e667'
down_revision = '6ab0ef651dcd'


def upgrade():
    # What we should be careful of: some production systems already have the index in place
    # since it was fixed by support
    idx_to_rename = {
        'auth_token_session_uuid_idx': 'auth_token__idx__session_uuid',
    }
    conn = op.get_bind()
    for idx, idx_renamed in idx_to_rename.items():
        conn.execute(f'ALTER INDEX IF EXISTS {idx} RENAME TO {idx_renamed};')

    conn.execute(
        'CREATE INDEX IF NOT EXISTS auth_token__idx__session_uuid ON auth_token (session_uuid);'
    )


def downgrade():
    op.drop_index('auth_token__idx__session_uuid')
