"""update_tables_to_cascade_delete

Revision ID: 1ad2bb5e31e6
Revises: 2610867a166b

"""

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '1ad2bb5e31e6'
down_revision = '2610867a166b'

tenant_tbl = sa.sql.table(
    'auth_tenant',
    sa.Column('uuid'),
    sa.Column('address_id')
)
address_tbl = sa.sql.table(
    'auth_address',
    sa.Column('id'),
    sa.Column('tenant_uuid')
)


def switch_address_foreign_key():
    op.add_column(
        'auth_address',
        sa.Column(
            'tenant_uuid',
            sa.String(38),
            sa.ForeignKey('auth_tenant.uuid', ondelete='CASCADE'),
            nullable=True,
        ),
    )
    sub_query = (
        sa.sql.select([tenant_tbl.c.uuid])
        .where(tenant_tbl.c.address_id == address_tbl.c.id)
    )
    op.execute(
        address_tbl
        .update()
        .values(tenant_uuid=sub_query)
    )
    op.execute(
        address_tbl
        .delete()
        .where(address_tbl.c.tenant_uuid == None)  # noqa
    )
    op.alter_column('auth_address', 'tenant_uuid', nullable=False)
    op.drop_column('auth_tenant', 'address_id')


def upgrade():
    switch_address_foreign_key()


def unswitch_address_foreign_key():
    op.add_column(
        'auth_address',
        sa.Column(
            'address_id',
            sa.Integer,
            sa.ForeignKey('auth_address.id', ondelete='SET NULL'),
        ),
    )

    sub_query = (
        sa.sql.select([address_tbl.c.id])
        .where(address_tbl.c.tenant_uuid == tenant_tbl.c.uuid)
    )
    op.execute(
        tenant_tbl
        .update()
        .values(address_id=sub_query)
    )
    op.drop_column('auth_address', 'tenant_uuid')


def downgrade():
    unswitch_address_foreign_key()
