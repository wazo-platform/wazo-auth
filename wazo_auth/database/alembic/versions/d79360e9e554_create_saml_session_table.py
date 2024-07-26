"""create saml session table

Revision ID: d79360e9e554
Revises: 036d80b11825

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd79360e9e554'
down_revision = '036d80b11825'

TABLE_NAME = 'auth_saml_session'

#     saml_session_id: str
# redirect_url: str
# domain: str
# relay_state: str
# login: str | None = None
# response: AuthnResponse | None = None
# start_time: datetime = field(default_factory=partial(datetime.now, timezone.utc))


def upgrade():
    op.create_table(
        TABLE_NAME,
        sa.Column(
            'request_id',
            sa.String(40),
            primary_key=True,
        ),
        sa.Column(
            'session_id',
            sa.String(22),
            primary_key=True,
        ),
        sa.Column(
            'redirect_url',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'domain',
            sa.String(512),
            nullable=False,
        ),
        sa.Column(
            'relay_state',
            sa.String(100),
            nullable=False,
        ),
        sa.Column(
            'login',
            sa.String(512),
            nullable=True,
        ),
        sa.Column(
            'start_time',
            sa.DateTime(timezone=True),
            server_default=sa.text('NOW()'),
            nullable=True,
        ),
    )


def downgrade():
    op.drop_table(TABLE_NAME)
