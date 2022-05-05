"""Change size of domain name field

Revision ID: 72c4a39fa885
Revises: 0c9ccb1b16a8

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '72c4a39fa885'
down_revision = '0c9ccb1b16a8'


def upgrade():
    op.alter_column('auth_tenant_domain', 'name', nullable=False, type_=sa.String(253))


def downgrade():
    op.alter_column('auth_tenant_domain', 'name', nullable=False, type_=sa.String(61))
