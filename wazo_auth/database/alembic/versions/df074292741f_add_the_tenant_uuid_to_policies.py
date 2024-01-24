"""add the tenant_uuid to policies

Revision ID: df074292741f
Revises: 87c21c795776

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'df074292741f'
down_revision = '87c21c795776'

TABLE = 'auth_policy'
COL = 'tenant_uuid'

policy_table = sa.sql.table('auth_policy', sa.Column('uuid'), sa.Column('tenant_uuid'))

tenant_table = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('parent_uuid'))
tenant_policy_table = sa.sql.table(
    'auth_tenant_policy', sa.Column('tenant_uuid'), sa.Column('policy_uuid')
)


def find_master_tenant():
    query = sa.sql.select([tenant_table.c.uuid]).where(
        tenant_table.c.uuid == tenant_table.c.parent_uuid
    )

    for row in op.get_bind().execute(query):
        return row.uuid

    raise Exception('Failed to find the TOP of the tenant tree')


def get_tenant_policy_associations():
    query = sa.sql.select(
        [tenant_policy_table.c.tenant_uuid, tenant_policy_table.c.policy_uuid]
    )

    assoc = {}
    for tenant_uuid, policy_uuid in op.get_bind().execute(query):
        if policy_uuid in assoc:
            continue
        assoc[policy_uuid] = tenant_uuid
    return assoc


def get_policies_tenant():
    query = sa.sql.select([policy_table.c.uuid, policy_table.c.tenant_uuid])
    assoc = {}
    for policy_uuid, tenant_uuid in op.get_bind().execute(query):
        assoc[policy_uuid] = tenant_uuid
    return assoc


def upgrade():
    master_tenant = find_master_tenant()
    op.add_column(
        TABLE,
        sa.Column(
            COL,
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            server_default=master_tenant,
            nullable=False,
        ),
    )
    op.alter_column(TABLE, COL, nullable=False, server_default=None)

    # If a policy was associated to a tenant set the tenant_uuid to one of the associated tenants
    for policy_uuid, tenant_uuid in get_tenant_policy_associations().items():
        filter_ = policy_table.c.uuid == policy_uuid
        query = policy_table.update().values(tenant_uuid=tenant_uuid).where(filter_)
        op.execute(query)

    op.drop_table('auth_tenant_policy')


def downgrade():
    op.create_table(
        'auth_tenant_policy',
        sa.Column(
            'tenant_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column(
            'policy_uuid',
            sa.String(38),
            sa.ForeignKey('auth_policy.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
    )

    for policy_uuid, tenant_uuid in get_policies_tenant().items():
        query = tenant_policy_table.insert().values(
            policy_uuid=policy_uuid, tenant_uuid=tenant_uuid
        )
        op.get_bind().execute(query)

    op.drop_column(TABLE, COL)
