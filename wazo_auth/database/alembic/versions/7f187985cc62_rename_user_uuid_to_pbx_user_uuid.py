"""rename user_uuid to pbx_user_uuid

Revision ID: 7f187985cc62
Revises: b92ed5aaff28

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '7f187985cc62'
down_revision = 'b92ed5aaff28'


def upgrade():
    op.alter_column(
        'auth_token', 'user_uuid', type_=sa.String(36), new_column_name='pbx_user_uuid'
    )


def downgrade():
    op.alter_column(
        'auth_token', 'pbx_user_uuid', type_=sa.String(38), new_column_name='user_uuid'
    )
