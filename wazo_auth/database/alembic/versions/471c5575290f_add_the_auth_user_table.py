"""add the auth_user table

Revision ID: 471c5575290f
Revises: 35bcf76df780

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '471c5575290f'
down_revision = '35bcf76df780'


def upgrade():
    op.create_table(
        'auth_user',
        Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('username', sa.String(128), unique=True, nullable=False),
        Column('password_hash', sa.Text, nullable=False),
        Column('password_salt', sa.LargeBinary, nullable=False),
    )
    op.create_table(
        'auth_email',
        Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        Column('address', sa.Text, unique=True, nullable=False),
        Column('confirmed', sa.Boolean, nullable=False, default=False),
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
        ),
    )
    op.add_column(
        'auth_user',
        Column(
            'main_email_uuid',
            sa.String(38),
            sa.ForeignKey('auth_email.uuid', ondelete='RESTRICT'),
        ),
    )


def downgrade():
    op.drop_column('auth_user', 'main_email_uuid')
    op.drop_table('auth_email')
    op.drop_table('auth_user')
