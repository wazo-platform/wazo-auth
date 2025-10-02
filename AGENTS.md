# AGENTS.md - Context for AI Tools

This file provides essential context about the wazo-auth project for AI coding assistants.

## Project Overview

wazo-auth is an authentication microservice for the Wazo platform that handles:

- User, group, and policy management
- Token creation and validation
- External authentication (LDAP, Google, Microsoft)
- SAML SSO integration
- Multi-tenant architecture

## Architecture

### Plugin-Based Architecture

The project uses a [stevedore](https://docs.openstack.org/stevedore/latest/user/index.html) plugin architecture with several plugin types defined in `setup.py`:

- **HTTP Plugins** (`wazo_auth.http`): API endpoints
   - Each plugin handles a specific API resource (users, tokens, groups, etc.)
   - Located in `wazo_auth/plugins/http/`
   - Each plugin has: `plugin.py`, `http.py`, `api.yml` (OpenAPI spec), `schemas.py`

- **Backend Plugins** (`wazo_auth.backends`): Authentication backends
   - `wazo_user`: Native Wazo user authentication
   - `ldap_user`: LDAP authentication
   - Located in `wazo_auth/plugins/backends/`

- **External Auth Plugins** (`wazo_auth.external_auth`): authentication credentials for external integrations
   - `google`, `microsoft`, `mobile`
   - Located in `wazo_auth/plugins/external_auth/`

- **Metadata Plugins** (`wazo_auth.metadata`): Token metadata providers
   - Located in `wazo_auth/plugins/metadata/`

- **IDP Plugins** (`wazo_auth.idp`): Identity providers
   - `saml`, `ldap`, `idp`, `refresh_token`
   - Located in `wazo_auth/plugins/idp/`

- **Email Notification Plugins** (`wazo_auth.email_notification`):
   - `smtp`: Email delivery
   - Located in `wazo_auth/plugins/email_notification/`

### Configuration

- Main config: `/etc/wazo-auth/config.yml`
- Override configs: `/etc/wazo-auth/conf.d/`
- Configuration loading in `wazo_auth/config.py`
- Plugin enabling/disabling via `enabled_http_plugins` config

### Database

- PostgreSQL with SQLAlchemy ORM
- Alembic migrations in `wazo_auth/database/alembic/`
- Models in `wazo_auth/database/models/`

## Development Workflow

### Virtual environments

- `tox` creates virtual environments for test environments defined in `tox.ini`, under the [`.tox`](.tox) subdirectory.

- To run arbitrary shell commands in a tox-managed virtual environment, one can use `tox exec -e<environment> -- <shell command>`, e.g. `tox exec -epy39 -- pip list`

- to create a development virtual environment independent of other tox testenvs, one can use `tox devenv .tox/cursor`; this environment must then be activated manually with `source .tox/cursor/bin/activate`.
### Testing

#### Unit Tests

- Located in `wazo_auth/tests/` and within individual plugin directories
- Run with: `tox -e py39`
- Use pytest with coverage reporting

#### Integration Tests

- Located in `integration_tests/suite/`
- Use Docker Compose to spin up required services
- Test actual HTTP APIs against running wazo-auth instance
- Run with: `tox -e integration`

#### Performance Tests

- Located in `integration_tests/performance_suite/`
- Run with: `tox -e performance`

#### Functional Tests

- Located in `integration_tests/functional_suite/`
- Use Playwright for browser automation (SAML testing)
- Run with: `tox -e functional`
- Requires SAML credentials via environment variables

### Linting and Code Quality

- Use pre-commit hooks for code formatting and linting
- Run with: `tox -e linters`
- Pre-commit runs automatically before commits
- Configured via `.pre-commit-config.yaml`

### Docker

- Main image: `wazoplatform/wazo-auth`
  built from `Dockerfile`
- Database image: `wazoplatform/wazo-auth-db`
  built from `contribs/docker/Dockerfile-db`
- Integration tests use docker-compose for service orchestration
  with compose files in `integration_tests/assets/`

## Common Patterns

### Plugin Structure

Each HTTP plugin typically follows this structure:

```
plugin_name/
├── __init__.py
├── plugin.py       # Plugin registration and initialization
├── http.py         # HTTP route handlers
├── api.yml         # OpenAPI specification
├── schemas.py      # Marshmallow validation schemas
└── tests/          # Unit tests for the plugin
```

### Service Layer

- Business logic in `wazo_auth/services/`
- Database operations through DAOs in `wazo_auth/database/`
- Plugin helpers in `wazo_auth/plugin_helpers/`

### HTTP Framework

- Flask-based HTTP server
- RESTful API design
- OpenAPI specifications for each plugin
- Error handling via custom exceptions in `wazo_auth/exceptions.py`

### Authentication Flow

- Token-based authentication
- ACL (Access Control List) validation
- Multi-tenant support via tenant UUID
- Token metadata for additional context

## Key Files and Directories

- `wazo_auth/main.py`: Application entry point
- `wazo_auth/controller.py`: Main application controller
- `wazo_auth/http_server.py`: HTTP server setup
- `wazo_auth/config.py`: Configuration management
- `wazo_auth/database/`: Database models and DAOs
- `wazo_auth/services/`: Business logic services
- `wazo_auth/plugins/`: All plugin implementations
- `integration_tests/`: Integration and functional tests
- `setup.py`: Plugin entry points and package configuration
- `tox.ini`: Test environment configuration

## External Dependencies

- PostgreSQL: Primary database
- RabbitMQ: Message bus (wazo-bus)
- Redis: Session storage and caching
- Docker: Development and testing environment
- Nginx: Reverse proxy (production)

## Development Environment

- Python 3.9+
- Use `wazo-auth-bootstrap` for initial setup
- Configuration in `/etc/wazo-auth/` for local development

## API Design

- RESTful endpoints following `/0.1/resource` pattern
- OpenAPI specifications in each plugin's `api.yml`
- Consistent error responses
- Tenant isolation via `Wazo-Tenant` header
- Token authentication via `X-Auth-Token` header or `Authorization: Bearer`

## Security Considerations

- Token-based authentication with configurable expiration
- ACL system for fine-grained permissions
- Multi-tenant isolation
- External authentication provider support
- SAML SSO integration
- Password reset and email confirmation flows
