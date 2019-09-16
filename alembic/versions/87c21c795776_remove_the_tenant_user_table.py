"""remove the tenant_user table

Revision ID: 87c21c795776
Revises: ab33c043b71e

"""

# revision identifiers, used by Alembic.
revision = '87c21c795776'
down_revision = 'ab33c043b71e'

from alembic import op
import sqlalchemy as sa


def upgrade():
    op.drop_table('auth_tenant_user')


def downgrade():
    op.create_table(
        'auth_tenant_user',
        sa.Column('tenant_uuid',
                  sa.String(38),
                  sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
                  primary_key=True),
        sa.Column('user_uuid',
                  sa.String(38),
                  sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
                  primary_key=True),
    )
