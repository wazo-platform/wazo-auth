"""add the auth_user_email table

Revision ID: 443b172ad7f6
Revises: 471c5575290f

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '443b172ad7f6'
down_revision = '471c5575290f'

auth_user_table = sa.sql.table('auth_user')


def upgrade():
    op.execute(auth_user_table.delete())
    op.create_table(
        'auth_user_email',
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'email_uuid',
            sa.String(38),
            sa.ForeignKey('auth_email.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column('main', sa.Boolean, nullable=False, default=False),
    )
    op.drop_column('auth_user', 'main_email_uuid')
    op.drop_column('auth_email', 'user_uuid')


def downgrade():
    op.drop_table('auth_user_email')
    op.add_column(
        'auth_user',
        Column(
            'main_email_uuid',
            sa.String(38),
            sa.ForeignKey('auth_email.uuid', ondelete='RESTRICT'),
        ),
    )
    op.add_column(
        'auth_email',
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
        ),
    )
