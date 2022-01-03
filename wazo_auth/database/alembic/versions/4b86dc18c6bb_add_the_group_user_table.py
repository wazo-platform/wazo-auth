"""add the group user table

Revision ID: 4b86dc18c6bb
Revises: 191d15471531

"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '4b86dc18c6bb'
down_revision = '191d15471531'

TABLE_NAME = 'auth_user_group'


def upgrade():
    op.create_table(
        TABLE_NAME,
        Column(
            'group_uuid',
            sa.String(38),
            sa.ForeignKey('auth_group.uuid', ondelete='CASCADE'),
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
    op.drop_table(TABLE_NAME)
