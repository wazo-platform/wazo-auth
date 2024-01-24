"""update_tables_to_cascade_delete

Revision ID: 1ad2bb5e31e6
Revises: 2610867a166b

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '1ad2bb5e31e6'
down_revision = '2610867a166b'

tenant_tbl = sa.sql.table('auth_tenant', sa.Column('uuid'), sa.Column('address_id'))
address_tbl = sa.sql.table('auth_address', sa.Column('id'), sa.Column('tenant_uuid'))
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
external_auth_config_tbl = sa.sql.table(
    'auth_external_auth_config',
    sa.Column('type_uuid'),
    sa.Column('tenant_uuid'),
    sa.Column('data_uuid'),
    sa.Column('data'),
)
user_external_auth_tbl = sa.sql.table(
    'auth_user_external_auth',
    sa.Column('user_uuid'),
    sa.Column('external_auth_type_uuid'),
    sa.Column('external_auth_data_uuid'),
    sa.Column('data'),
)
external_auth_data_tbl = sa.sql.table(
    'auth_external_auth_data',
    sa.Column('uuid'),
    sa.Column('data'),
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
    sub_query = sa.sql.select([tenant_tbl.c.uuid]).where(
        tenant_tbl.c.address_id == address_tbl.c.id
    )
    op.execute(address_tbl.update().values(tenant_uuid=sub_query))
    op.execute(address_tbl.delete().where(address_tbl.c.tenant_uuid == None))  # noqa
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
    user_sub_query = sa.sql.select([user_email_tbl.c.user_uuid]).where(
        user_email_tbl.c.email_uuid == email_tbl.c.uuid
    )
    main_sub_query = sa.sql.select([user_email_tbl.c.main]).where(
        user_email_tbl.c.email_uuid == email_tbl.c.uuid
    )
    op.execute(email_tbl.update().values(user_uuid=user_sub_query, main=main_sub_query))
    op.execute(email_tbl.delete().where(email_tbl.c.user_uuid == None))  # noqa
    op.execute(email_tbl.delete().where(email_tbl.c.main == None))  # noqa
    op.alter_column('auth_email', 'user_uuid', nullable=False)
    op.alter_column('auth_email', 'main', nullable=False)
    op.drop_table('auth_user_email')


def merge_external_auth_data_with_external_auth_config():
    op.add_column(
        'auth_external_auth_config',
        sa.Column('data', sa.Text, nullable=True),
    )
    sub_query = sa.sql.select([external_auth_data_tbl.c.data]).where(
        external_auth_config_tbl.c.data_uuid == external_auth_data_tbl.c.uuid
    )
    op.execute(external_auth_config_tbl.update().values(data=sub_query))
    op.execute(
        external_auth_config_tbl.delete().where(
            external_auth_config_tbl.c.data == None  # noqa
        )
    )
    op.alter_column('auth_external_auth_config', 'data', nullable=False)
    op.drop_column('auth_external_auth_config', 'data_uuid')


def merge_external_auth_data_with_user_external_auth():
    op.add_column(
        'auth_user_external_auth',
        sa.Column('data', sa.Text, nullable=True),
    )
    sub_query = sa.sql.select([external_auth_data_tbl.c.data]).where(
        user_external_auth_tbl.c.external_auth_data_uuid
        == external_auth_data_tbl.c.uuid
    )
    op.execute(user_external_auth_tbl.update().values(data=sub_query))
    op.execute(
        user_external_auth_tbl.delete().where(
            user_external_auth_tbl.c.data == None  # noqa
        )
    )
    op.alter_column('auth_user_external_auth', 'data', nullable=False)
    op.drop_column('auth_user_external_auth', 'external_auth_data_uuid')


def upgrade():
    switch_address_foreign_key()
    remove_middle_table_between_user_email()
    merge_external_auth_data_with_external_auth_config()
    merge_external_auth_data_with_user_external_auth()
    op.drop_table('auth_external_auth_data')


def unswitch_address_foreign_key():
    op.add_column(
        'auth_address',
        sa.Column(
            'address_id',
            sa.Integer,
            sa.ForeignKey('auth_address.id', ondelete='SET NULL'),
        ),
    )

    sub_query = sa.sql.select([address_tbl.c.id]).where(
        address_tbl.c.tenant_uuid == tenant_tbl.c.uuid
    )
    op.execute(tenant_tbl.update().values(address_id=sub_query))
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
            user_email_tbl.insert().values(
                user_uuid=email.user_uuid,
                email_uuid=email.uuid,
                main=email.main,
            )
        )

    op.drop_column('auth_email', 'user_uuid')
    op.drop_column('auth_email', 'main')


def unmerge_external_auth_data_with_external_auth_config():
    op.add_column(
        'auth_external_auth_config',
        sa.Column(
            'data_uuid',
            sa.String(36),
            sa.ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'),
        ),
    )

    external_auths = op.get_bind().execute(sa.sql.select([external_auth_config_tbl]))
    for external_auth in external_auths:
        data_uuid = (
            op.get_bind()
            .execute(
                external_auth_data_tbl.insert()
                .returning(external_auth_data_tbl.c.uuid)
                .values(data=external_auth.data)
            )
            .scalar()
        )
        op.execute(
            external_auth_config_tbl.update()
            .where(external_auth_config_tbl.c.type_uuid == external_auth.type_uuid)
            .where(external_auth_config_tbl.c.tenant_uuid == external_auth.tenant_uuid)
            .values(data_uuid=data_uuid)
        )

    op.drop_column('auth_external_auth_config', 'data')


def unmerge_external_auth_data_with_user_external_auth():
    op.add_column(
        'auth_user_external_auth',
        sa.Column(
            'external_auth_data_uuid',
            sa.String(38),
            sa.ForeignKey('auth_external_auth_data.uuid', ondelete='CASCADE'),
            primary_key=True,
            nullable=True,
        ),
    )

    external_auths = op.get_bind().execute(sa.sql.select([user_external_auth_tbl]))
    for external_auth in external_auths:
        data_uuid = (
            op.get_bind()
            .execute(
                external_auth_data_tbl.insert()
                .returning(external_auth_data_tbl.c.uuid)
                .values(data=external_auth.data)
            )
            .scalar()
        )
        op.execute(
            user_external_auth_tbl.update()
            .where(user_external_auth_tbl.c.user_uuid == external_auth.user_uuid)
            .where(
                user_external_auth_tbl.c.external_auth_type_uuid
                == external_auth.external_auth_type_uuid
            )
            .values(external_auth_data_uuid=data_uuid)
        )

    op.alter_column(
        'auth_user_external_auth', 'external_auth_data_uuid', nullable=False
    )
    op.drop_column('auth_user_external_auth', 'data')


def downgrade():
    unswitch_address_foreign_key()
    add_middle_table_between_user_email()
    op.create_table(
        'auth_external_auth_data',
        sa.Column(
            'uuid',
            sa.String(38),
            server_default=sa.text('uuid_generate_v4()'),
            primary_key=True,
        ),
        sa.Column('data', sa.Text, nullable=False),
    )
    unmerge_external_auth_data_with_external_auth_config()
    unmerge_external_auth_data_with_user_external_auth()
