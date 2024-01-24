"""add group policy association

Revision ID: 4edfead052cd
Revises: 4b86dc18c6bb

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = '4edfead052cd'
down_revision = '4b86dc18c6bb'


TABLE_NAME = 'auth_group_policy'


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
            'policy_uuid',
            sa.String(38),
            sa.ForeignKey('auth_policy.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
