"""add prefix to duplicates usernames and email addresses

Revision ID: 8a04704df15a
Revises: 07a6bb53c284

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '8a04704df15a'
down_revision = '07a6bb53c284'

USERNAME_IDX = 'auth_user_username_key'
EMAIL_IDX = 'auth_email_address_key'

users_tbl = sa.sql.table(
    'auth_user',
    sa.Column('uuid'),
    sa.Column('username'),
)

email_tbl = sa.sql.table(
    'auth_email',
    sa.Column('uuid'),
    sa.Column('address'),
)


def find_all_usernames():
    query = sa.sql.select([users_tbl.c.uuid, users_tbl.c.username])
    return op.get_bind().execute(query).fetchall()


def find_all_emails():
    query = sa.sql.select([email_tbl.c.uuid, email_tbl.c.address])
    return op.get_bind().execute(query).fetchall()


def find_duplicates(results):
    duplicates = {}
    only_lowercase_values = [
        value.lower() for (_, value) in results if value is not None
    ]

    for uuid, value in results:
        if value is None:
            continue
        lower_value = value.lower()
        value_count = only_lowercase_values.count(lower_value)
        if value_count > 1:
            current_duplicates = duplicates.get(lower_value, [])
            current_duplicates.append({'uuid': uuid, 'value': value})
            duplicates[lower_value] = current_duplicates

    return duplicates


def fix_duplicate(duplicates, table, field_name):
    for username, duplicate in duplicates.items():
        duplicate_counter = 0
        for dup_user in duplicate[1:]:
            new_value = f"duplicate{duplicate_counter}_{dup_user['value']}"
            print(
                'Renaming duplicate {} {} to {}'.format(
                    field_name, dup_user['value'], new_value
                )
            )
            query = (
                sa.sql.update(table)
                .where(table.c.uuid == dup_user['uuid'])
                .values(**{field_name: new_value})
            )
            op.get_bind().execute(query)
            duplicate_counter += 1


def upgrade():
    duplicate_usernames = find_duplicates(find_all_usernames())
    fix_duplicate(duplicate_usernames, users_tbl, 'username')
    duplicate_emails = find_duplicates(find_all_emails())
    fix_duplicate(duplicate_emails, email_tbl, 'address')

    op.drop_constraint(USERNAME_IDX, 'auth_user')
    op.create_index(
        USERNAME_IDX, 'auth_user', [sa.text('lower(username)')], unique=True
    )
    op.drop_constraint(EMAIL_IDX, 'auth_email')
    op.create_index(EMAIL_IDX, 'auth_email', [sa.text('lower(address)')], unique=True)


def downgrade():
    op.drop_index(USERNAME_IDX, 'auth_user')
    op.create_unique_constraint(USERNAME_IDX, 'auth_user', ['username'])
    op.drop_index(EMAIL_IDX, 'auth_email')
    op.create_unique_constraint(EMAIL_IDX, 'auth_email', ['address'])
