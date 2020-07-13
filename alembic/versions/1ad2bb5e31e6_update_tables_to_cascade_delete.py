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
user_email_tbl = sa.sql.table(
    'auth_user_email',
    sa.Column('user_uuid'),
    sa.Column('email_uuid'),
    sa.Column('main'),
)
email_tbl = sa.sql.table(
    'auth_email',
    sa.Column('uuid'),
    sa.Column('user_uuid'),
    sa.Column('main'),
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


def remove_middle_table_between_user_email():
    op.add_column('auth_email', sa.Column('main', sa.Boolean, nullable=True))
    op.add_column(
        'auth_email',
        sa.Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
            nullable=True,
        ),
    )
    user_sub_query = (
        sa.sql.select([user_email_tbl.c.user_uuid])
        .where(user_email_tbl.c.email_uuid == email_tbl.c.uuid)
    )
    main_sub_query = (
        sa.sql.select([user_email_tbl.c.main])
        .where(user_email_tbl.c.email_uuid == email_tbl.c.uuid)
    )
    op.execute(
        email_tbl
        .update()
        .values(user_uuid=user_sub_query, main=main_sub_query)
    )
    op.execute(
        email_tbl
        .delete()
        .where(email_tbl.c.user_uuid == None)  # noqa
    )
    op.alter_column('auth_email', 'user_uuid', nullable=False)
    op.drop_table('auth_user_email')


def upgrade():
    switch_address_foreign_key()
    remove_middle_table_between_user_email()


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


def add_middle_table_between_user_email():
    op.create_table(
        'auth_user_email',
        sa.Column(
            'user_uuid',
            sa.String(38),
            sa.ForeignKey('auth_user.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column(
            'email_uuid',
            sa.String(38),
            sa.ForeignKey('auth_email.uuid', ondelete='CASCADE'),
            primary_key=True,
        ),
        sa.Column('main', sa.Boolean, nullable=False, default=False),
    )

    emails = op.get_bind().execute(sa.sql.select([email_tbl]))
    for email in emails:
        op.execute(
            user_email_tbl
            .insert()
            .values(
                user_uuid=email.user_uuid,
                email_uuid=email.uuid,
                main=email.main,
            )
        )

    op.drop_column('auth_email', 'user_uuid')
    op.drop_column('auth_email', 'main')


def downgrade():
    unswitch_address_foreign_key()
    add_middle_table_between_user_email()
