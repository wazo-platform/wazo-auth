"""add the tenant user table

Revision ID: c11c395a7b6
Revises: ca69b099820

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = 'c11c395a7b6'
down_revision = 'ca69b099820'


def upgrade():
    op.create_table(
        'auth_tenant_user',
        Column(
            'tenant_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )


def downgrade():
    op.drop_table('auth_tenant_user')
