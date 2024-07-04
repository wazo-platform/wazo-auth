"""native-user

Revision ID: 1cd6161394d0
Revises: a1149ec5ad50

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '1cd6161394d0'
down_revision = 'a1149ec5ad50'

user_table = sa.sql.table(
    'auth_user',
    sa.Column('authentication_method', sa.Text),
    sa.Column('purpose', sa.Text),
)


def upgrade():
    query = (
        user_table.update()
        .values(authentication_method='native')
        .where(
            sa.or_(
                user_table.c.purpose == 'internal',
                user_table.c.purpose == 'external_api',
            )
        )
    )
    op.execute(query)


def downgrade():
    pass
