"""set-default-policy-managed

Revision ID: caede349e1ab
Revises: 23a680f792f5

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'caede349e1ab'
down_revision = '23a680f792f5'

policy_tbl = sa.sql.table(
    'auth_policy',
    sa.Column('name'),
    sa.Column('config_managed'),
)

DEFAULT_POLICIES = [
    'wazo_default_user_policy',
    'wazo_default_admin_policy',
]


def upgrade():
    query = (
        policy_tbl.update()
        .values(config_managed=True)
        .where(policy_tbl.c.name.in_(DEFAULT_POLICIES))
    )
    op.execute(query)


def downgrade():
    query = (
        policy_tbl.update()
        .values(config_managed=False)
        .where(policy_tbl.c.name.in_(DEFAULT_POLICIES))
    )
    op.execute(query)
