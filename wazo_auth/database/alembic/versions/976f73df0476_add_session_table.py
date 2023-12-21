"""add_session_table

Revision ID: 976f73df0476
Revises: 21ad58426cbd

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '976f73df0476'
down_revision = '21ad58426cbd'

token_table = sa.sql.table('auth_token', sa.Column('uuid'), sa.Column('session_uuid'))


def upgrade():
    op.create_table(
        'auth_session',
        sa.Column(
            'uuid',
            sa.String(36),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        sa.Column('mobile', sa.Boolean, nullable=False, default=False),
    )
    op.add_column(
        'auth_token',
        sa.Column(
            'session_uuid',
            sa.String(36),
            sa.ForeignKey('auth_session.uuid', ondelete='CASCADE'),
            nullable=True,
        ),
    )

    _create_sessions_to_existing_tokens()

    op.alter_column('auth_token', 'session_uuid', nullable=False)


def _create_sessions_to_existing_tokens():
    session_table = sa.sql.table('auth_session', sa.Column('uuid'), sa.Column('mobile'))

    query = sa.sql.select([token_table.c.uuid])
    tokens = op.get_bind().execute(query)
    for token in tokens:
        query = (
            session_table.insert().returning(session_table.c.uuid).values(mobile=False)
        )
        session_uuid = op.get_bind().execute(query).scalar()
        query = (
            token_table.update()
            .values(session_uuid=session_uuid)
            .where(token_table.c.uuid == token.uuid)
        )
        op.execute(query)


def downgrade():
    op.drop_column('auth_token', 'session_uuid')
    op.drop_table('auth_session')
