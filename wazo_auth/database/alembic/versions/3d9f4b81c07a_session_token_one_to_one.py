"""a session references a single token

Revision ID: 3d9f4b81c07a
Revises: 1c862ebfbb3a

"""

import uuid

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '3d9f4b81c07a'
down_revision = '1c862ebfbb3a'

TABLE_NAME = 'auth_token'
CONSTRAINT_NAME = 'auth_token_session_uuid_key'
INDEX_NAME = 'auth_token__idx__session_uuid'

auth_token = sa.table(
    'auth_token',
    sa.column('uuid', sa.String),
    sa.column('session_uuid', sa.String),
    sa.column('issued_t', sa.Integer),
)

auth_session = sa.table(
    'auth_session',
    sa.column('uuid', sa.String),
    sa.column('tenant_uuid', sa.String),
    sa.column('mobile', sa.Boolean),
)


def _tokens_sharing_a_session():
    position = (
        sa.func.row_number()
        .over(
            partition_by=auth_token.c.session_uuid,
            order_by=[auth_token.c.issued_t.desc(), auth_token.c.uuid],
        )
        .label('position')
    )
    ranked = sa.select(
        auth_token.c.uuid.label('token_uuid'),
        auth_token.c.session_uuid,
        position,
    ).subquery()

    # the most recent token keeps the session, the others are moved away
    return (
        sa.select(
            ranked.c.token_uuid,
            auth_session.c.tenant_uuid,
            auth_session.c.mobile,
        )
        .select_from(
            ranked.join(auth_session, auth_session.c.uuid == ranked.c.session_uuid)
        )
        .where(ranked.c.position > 1)
    )


def upgrade():
    # tokens sharing a session predate the invariant. They are given a session
    # of their own, copied from the one they shared, rather than being revoked.
    shared_tokens = op.get_bind().execute(_tokens_sharing_a_session()).fetchall()
    new_sessions = [
        {
            'uuid': str(uuid.uuid4()),
            'tenant_uuid': token.tenant_uuid,
            'mobile': token.mobile,
        }
        for token in shared_tokens
    ]

    if new_sessions:
        op.bulk_insert(auth_session, new_sessions)
        for token, session in zip(shared_tokens, new_sessions):
            op.execute(
                sa.update(auth_token)
                .where(auth_token.c.uuid == token.token_uuid)
                .values(session_uuid=session['uuid'])
            )

    op.create_unique_constraint(CONSTRAINT_NAME, TABLE_NAME, ['session_uuid'])
    # the index of the unique constraint serves the lookups by session
    op.drop_index(INDEX_NAME, table_name=TABLE_NAME)


def downgrade():
    op.create_index(INDEX_NAME, TABLE_NAME, ['session_uuid'])
    op.drop_constraint(CONSTRAINT_NAME, TABLE_NAME, type_='unique')
