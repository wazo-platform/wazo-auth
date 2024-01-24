import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import create_engine

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.get_main_option('configure_logging', 'true') == 'true':
    fileConfig(config.config_file_name)

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.

VERSION_TABLE = 'alembic_version_auth'
URI = os.getenv('ALEMBIC_DB_URI', None)


def get_url():
    # The import should not be top level to allow the usage of the ALEMBIC_DB_URI
    # environment variable when the DB is not hosted on the same host as wazo-auth.
    # When building the docker image for the database for example.
    from wazo_auth.config import get_config

    wazo_config = get_config('')
    return wazo_config.get('db_uri')


def run_migrations_offline():
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = URI or config.get_main_option("sqlalchemy.url") or get_url()
    context.configure(url=url, version_table=VERSION_TABLE)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
    url = URI or config.get_main_option("sqlalchemy.url") or get_url()
    engine = create_engine(url)

    connection = engine.connect()
    context.configure(connection=connection, version_table=VERSION_TABLE)

    try:
        with context.begin_transaction():
            context.run_migrations()
    finally:
        connection.close()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
