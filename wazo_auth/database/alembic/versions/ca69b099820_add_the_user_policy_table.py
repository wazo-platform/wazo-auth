"""add the user_policy table

Revision ID: ca69b099820
Revises: 3beeaef02651

"""

import sqlalchemy as sa
from alembic import op
from sqlalchemy.schema import Column

# revision identifiers, used by Alembic.
revision = 'ca69b099820'
down_revision = '3beeaef02651'


def upgrade():
    op.create_table(
        'auth_user_policy',
        Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
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
    op.drop_table('auth_user_email')
