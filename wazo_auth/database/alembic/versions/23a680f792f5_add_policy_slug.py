"""add-policy-slug

Revision ID: 23a680f792f5
Revises: 9b80db8b7860

"""

import random
import re
import string

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '23a680f792f5'
down_revision = '9b80db8b7860'

MAX_SLUG_LEN = 80
SLUG_LEN = 3
IDX_NAME = 'auth_policy__idx__slug'

policy_tbl = sa.sql.table(
    'auth_policy',
    sa.Column('uuid'),
    sa.Column('name'),
    sa.Column('tenant_uuid'),
    sa.Column('slug'),
)

tenant_tbl = sa.sql.table(
    'auth_tenant',
    sa.Column('uuid'),
)


def _slug_from_name(name):
    if not name:
        return
    return re.sub(r'[^a-zA-Z0-9_-]', '', name)[:MAX_SLUG_LEN]


def _generate_random_slug():
    choices = string.ascii_lowercase + string.digits
    return ''.join(random.choice(choices) for _ in range(SLUG_LEN))


def upgrade():
    op.add_column('auth_policy', sa.Column('slug', sa.String(MAX_SLUG_LEN)))
    columns = '((lower(slug)), tenant_uuid)'
    op.execute(f'CREATE UNIQUE INDEX {IDX_NAME} ON auth_policy {columns};')

    query = sa.sql.select([tenant_tbl.c.uuid])
    for tenant in op.get_bind().execute(query):
        slugs = set()
        query = sa.sql.select([policy_tbl.c.uuid, policy_tbl.c.name]).where(
            policy_tbl.c.tenant_uuid == tenant.uuid
        )
        for policy in op.get_bind().execute(query):
            slug = _slug_from_name(policy.name)
            if slug.lower() in slugs:
                slug = None

            if not slug:
                while True:
                    slug = _generate_random_slug()
                    if slug not in slugs:
                        break

            slugs.add(slug.lower())
            op.execute(
                policy_tbl.update()
                .values(slug=slug)
                .where(policy_tbl.c.uuid == policy.uuid)
            )

    op.alter_column('auth_policy', 'slug', nullable=False)


def downgrade():
    op.drop_index(IDX_NAME)
    op.drop_column('auth_policy', 'slug')
