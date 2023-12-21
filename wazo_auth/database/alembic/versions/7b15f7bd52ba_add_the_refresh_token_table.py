"""add the refresh_token table

Revision ID: 7b15f7bd52ba
Revises: 7c7c2fc280ca

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '7b15f7bd52ba'
down_revision = '7c7c2fc280ca'


def upgrade():
    op.create_table(
        'auth_refresh_token',
        Column(
            'uuid',
            sa.String(36),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('client_id', sa.Text),
        Column(
            'user_uuid',
            sa.String(36),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
        ),
        Column('backend', sa.Text),
        Column('login', sa.Text),
        Column('user_agent', sa.Text),
        Column('remote_addr', sa.Text),
    )
    op.create_unique_constraint(
        'auth_refresh_token_client_id_user_uuid',
        'auth_refresh_token',
        ['client_id', 'user_uuid'],
    )


def downgrade():
    op.drop_table('auth_refresh_token')
