# Changelog

## 25.09

* Added metadata to refresh tokens. `/0.1/tokens` exposes new `metadata` field.

## 25.08

* wazo_auth.idp plugin interface now supports `get_backend` method for refresh token interoperability

## 25.02

* Allow to customize the way to send email through Stevedore entry points

## 24.08

* The following resources have been added
  * GET `0.1/idp`
  * PUT `0.1/idp/<idp_type>/users/<user_uuid>`
  * DELETE `0.1/idp/<idp_type>/users/<user_uuid>`
  * PUT `0.1/idp/<idp_type>/users`

* The `backend` parameter during token creation is now ignored. The configured authentication method of the user or tenant is used instead.

* The `tenants` resource now has the `default_authentication_method` field which can contain the following values

  * `native`
  * `ldap`
  * `saml`

* The `users` resource now has the `authentication_method` field which can contain the following values

  * `default`
  * `native`
  * `ldap`
  * `saml`

* The following resources have been added allowing users to login using SAML2

  * `POST /saml/sso`
  * `POST /saml/acs`


## 24.07

* The external API `POST /external/mobile/config` accepts a new key:

  * `fcm_service_account_info`

* The external API `POST /external/mobile/config` has a deprecated key:

  * `fcm_api_key`

## 24.06

* The config has new available keys:

  * `profiling_enabled: bool`

Those keys may also be configured with PATCH `/0.1/config`.

## 24.01

* The following deprecated endpoints have been removed

  * GET `0.1/tenants/<tenant_uuid>/policies`
  * GET `0.1/tenants/<tenant_uuid>/users`
  * GET `0.1/users/<user_uuid>/tenants`

## 23.17

* Tokens now have a maximum expiration time of 10 years.

## 23.07

* The following CLI options have been added
  * `--listen-port` will override the HTTP server listening port
  * `--log-file` will override the log filename
* `update_policy_on_startup` can now be disabled from the configuration file
* `token_cleanup_interval` will now disable the cleanup mechanism if set to `0`

## 23.02

* Username and e-mail addresses are now unique in a case insensitive way. This means that a user
  with username `Bob` is now considered the same as a user with the username `bob`. Duplicates that
  may be already present in the database will be prefixed with `duplicateXX`, `XX` being the occurence.

## 23.01

* `GET /external/{auth_type}/users`: no longer discards user without an active session with the stack, all users with a token with the service will be returned

## 22.17

* Added a new endpoint to retrieve the list of connected users registered with the specified auth type

  * `GET /external/{auth_type}/users`

## 22.13

* Adding a user to a group in `/user_group` endpoint should fail now when the two resources do not have/belong to the same tenant; it raises a 400 HTTP error

## 22.11

* The endpoint `GET /users/password/reset` now accepts `login` query string

## 22.10

* New configuration has been added to configure number of proxies ahead this service and get the
  right client IP

  ```
  rest_api:
    num_proxies: 1
  ```

* The endpoint `GET /groups` now accepts the following query string parameters:

  * `policy_uuid`: filter groups that have this policy
  * `policy_slug`: idem with policy slug

* The groups endpoints now accept and return the group attribute `slug`:

  * `GET/POST /groups`
  * `GET/PUT /groups`

## 22.09

* The endpoint `GET /users` now accepts the following query string parameters:

  * `policy_uuid`: filter users that have this policy (no indirect relation)
  * `policy_slug`: idem with policy slug
  * `has_policy_uuid`: filter users that have this policy, either directly or indirectly via a group policy
  * `has_policy_slug`: idem with policy slug

## 22.07

The `POST /0.1/token` endpoint now accepts the following body parameters:

  * `domain_name`: mandatory for `ldap_user` backend

The following body parameters have been deprecated on the `POST /0.1/token` endpoint:

  * `tenant_id` use the `domain_name` parameter instead

* The following field:

  * `domain_names`

has been added to the following resources:

  * `tenants`

supporting the following operations:

  * `GET /tenants/domain_name`
  * `PUT /tenants/{tenant_uuid}/domain_names`
  * `DELETE /tenants/{tenant_uuid}/domain_names`
  * `POST /tenants/{tenant_uuid}/domain_names`


## 22.03

* New endpoint to get and update configuration of the LDAP authentication source:

  * `GET /backends/ldap`
  * `PUT /backends/ldap`
  * `DELETE /backends/ldap`

  * The `POST /0.1/token` endpoint now accepts the following body paremeters

    * `tenant_id`: mandatory for `ldap_user` backend

## 22.01

* The `users` resource does not require a `username` anymore
* The `token` resource now works with the `username` or a confirmed email address

## 21.15

* The `policies` resource now has a `shared` field

## 21.14

* New `default_user_policy` configuration has been added to apply this policy to all users
* `backend_policies` has been deprecated and will be removed in further version

## 21.10

* Forbid to delete its own tenant

## 21.09

* Policies endpoints now check that token has enough permission to assign access. To follow this
  change, the bootstrap user (i.e. wazo-auth-cli) has now all accesses (i.e. '#')
* Policy's slug can now be used as identifier instead of UUID in endpoints
* New endpoint to get and update configuration of `wazo-auth`:

  * `GET /config`
  * `PATCH /config`
    * Only the `debug` attribute may be modified.

## 21.07

* The `policies` resource now has a `read_only` field
* The `groups` resource now has a `read_only` field
* The field `system_managed` has been deprecated in `groups` resources:

## 21.05

* The `policies` resource now has a `slug` field
* The following deprecated resources have been removed

  * `DELETE /policies/{policy_uuid}/acl_templates/{template}`
  * `PUT /policies/{policy_uuid}/acl_templates/{template}`

* The deprecated field `acl_templates` has been removed in the following routes:

  * `GET /policies`
  * `GET /policies/{policy_uuid}`
  * `GET /groups/{group_uuid}/policies`

* The deprecated field `acls` has been removed for token resource
* The deprecated method `get_acls` for backend has been removed

## 21.04

* The `tenants` resource now has a `slug` field

## 20.16

* The following token metadata for `wazo_default_user` backend plugin has been removed:

  * `username`
  * `groups`
  * `visible_tenants`
  * `xivo_user_uuid`

* Template feature for an access (acl) has been removed
* A new resources have been added to manage policy an access

  * `DELETE /policies/{policy_uuid}/acl/{access}`
  * `PUT /policies/{policy_uuid}/acl/{access}`

* The following resources have been deprecated

  * `DELETE /policies/{policy_uuid}/acl_templates/{template}`
  * `PUT /policies/{policy_uuid}/acl_templates/{template}`

* The field `acl_templates` has been deprecated in the following routes:

  * `GET /policies`
  * `GET /policies/{policy_uuid}`
  * `GET /groups/{group_uuid}/policies`

* The field `acls` has been deprecated in favor of the new `acl` field for token resource

## 20.13

* An ACL template can now begin with the character `!` to remove permissions explicitly.
* A new resource has been added to check multiple permissions:

  * POST `/0.1/token/{token_uuid}/scopes/check`

## 20.06

* Deprecate SSL configuration

## 20.05

* A new resource has been added to check the service status

  * HEAD `0.1/status`

* The following new fields

  * `apns_voip_token`
  * `apns_notification_token`

  have been added in the following routes:

  * `GET /users/{user_uuid}/external/mobile`
  * `POST /users/{user_uuid}/external/mobile`

* The field `apns_token` has been deprecated in the following routes:

  * `GET /users/{user_uuid}/external/mobile`
  * `POST /users/{user_uuid}/external/mobile`

  This field will be removed in a later version.

## 19.16

* wazo-auth-bootstrap setup is a noop
* wazo-auth-bootstrap complete now directly connect to the database
* wazo-auth-bootstrap initial-user have been added to simplify container setup.
* `0.1/init` endpoint have been removed
* The refresh tokens list now shows if a mobile session created that refresh token
* A new resource as been added to list refresh tokens for the whole system

## 19.14

* A new resource has been added to manage refresh tokens

  * GET `0.1/users/<user_uuid>/tokens`
  * DELETE `0.1/users/<user_uuid>/tokens/<client_id>`

## 19.13

* The `0.1/token` resource now accept the following optionnal body paremeters

  * `client_id`
  * `refresh_token`
  * `access_type`

## 19.10

* New resource has been added to delete a session

  * DELETE `0.1/sessions/<session_uuid>`
  * DELETE `0.1/users/<user_uuid>/sessions/<session_uuid>`

* New resource has been added to manage external auth mobile sender ids

  * GET `0.1/users/<user_uuid>/external/mobile/sender_id`

## 19.09

* The ACL on `0.1/external/<auth_type>/config` have been change to match the URL

## 19.05

* New resource has been added to manage config for a given auth_type

  * GET `0.1/external/<auth_type>/config`
  * POST `0.1/external/<auth_type>/config`
  * DELETE `0.1/external/<auth_type>/config`
  * PUT `0.1/external/<auth_type>/config`

## 19.04

* The `tenants` field has been removed from token metadata
* New resource has been added to list user's sessions

  * GET `0.1/users/<user_uuid>/sessions`

## 19.03

* New resource has been added to list sessions

  * GET `0.1/sessions`

## 19.02

* Old method `get_ids` for backend has been removed
* GET on `/users/password/reset` does not delete the current password anymore

## 19.01

* The backend `xivo_admin` has been removed

## 18.14

* The backend option in `POST /tokens` is now optional. The default value is `wazo_user`
* The backend `xivo_service` has been removed

## 18.13

* `POST /init` can now take the purpose attribute
* A user now has a `purpose` property
* The following URLs have been deprecated. Use `Wazo-Tenant` header instead:

  * GET `0.1/tenants/<tenant_uuid>/policies`
  * GET `0.1/tenants/<tenant_uuid>/users`
  * GET `0.1/users/<user_uuid>/tenants`

## 18.06

* Groups now have a tenant_uuid

  * POST on /groups will create the group in the token's user tenant_uuid or in the specified Wazo-Tenant
  * add tenant filtering on the following endpoints

    * GET, PUT, DELETE `/groups/<group_uuid>/users`
    * GET /users/<user_uuid>/groups
    * GET, PUT, DELETE `/groups/<group_uuid>`
    * GET /groups

## 18.05

* GET and HEAD on /token now accept the "tenant" query string argument and will return 403 if the tenant is not in the user's authorized tenants.
* The following route are now tenant filtered using the token owner's tenant of the Wazo-Tenant header

  * POST, GET /policies
  * GET, PUT, DELETE /policies/<policy_uuid>
  * PUT, DELETE /policies/<policy_uuid>/acl_templates/:acl_template
  * GET /tenants/<tenant_uuid>/policies

* A policy now has a `tenant_uuid` which is the owning tenant of the policy
* The GET /policies/<policy_uuid>/tenants route has been removed
* The following route have been removed

  * PUT, DELETE /tenants/<tenant_uuid>/policies/<policy_uuid>

## 18.04

* Add the `uuid` field on POST `0.1/tenants`
* A user now has a tenant_uuid. It is either:

  * the creator's tenant_uuid
  * the specified Wazo-Tenant header's value

* A tenant now has a parent_uuid which is the tenant_uuid of the tenant above this tenant in the hierarchy.
* The GET /tenants only return tenants that are below the tenant_uuid of the user doing the request or specified by Wazo-Tenant
* The GET /users only return user from the same tenant as the requester or Wazo-Tenant
* The recurse parameter has been added on /users to include users from all sub-tenants

## 18.03

* Add the "enabled" field to a users
* New resources have been added to update all of a user's emails

  * PUT `0.1/admin/users/<user_uuid>/emails`
  * PUT `0.1/users/<user_uuid>/emails`

* The "username" field of a user can now be 256 characters long

* Add an association between tenants and policies

  * PUT `0.1/tenants/<tenant_uuid>/policies/<policy_uuid>`
  * DELETE `0.1/tenants/<tenant_uuid>/policies/<policy_uuid>`
  * GET `0.1/tenants/<tenant_uuid>/policies/`
  * GET `0.1/policies/<policy_uuid>/tenants/`

## 18.02

* A new resource has been added to trigger a new email confirmation email

  * GET `0.1/users/<user_uuid>/emails/<email_uuid>/confirm`

* Add the "metadata" field on the token body

  * POST `0.1/token`
  * GET `0.1/token/<token_uuid>`

## 18.01

* Add the `firstname` and `lastname` fields to a user
* The `name` of a tenant is now optional
* A new resource has been added to list a user external authencation methods

  * GET `0.1/users/<user_uuid>/external`

* The `email_address` field is no longer required when creating a user
* Add a new URL to edit users

  * PUT `0.1/users/<user_uuid>`

* Add a new URL to edit tenants

  * PUT `0.1/tenants/<tenant_uuid>`

* A tenant now accepts the following fields:

  * phone: The tenant's phone number to reach the contact
  * contact: The user UUID of the user to contact for this tenant
  * address: The tenant's address

    * line_1
    * line_2
    * city
    * state
    * country
    * zip_code

* Add a new route to change reset the user's password when forgotten

  * GET /users/password/reset
  * POST /users/password/reset

## 17.17

* A new resource has been added to assign a User to a Group

  * PUT `0.1/groups/<group_uuid>/users/<user_uuid>`
  * DELETE `0.1/groups/<group_uuid>/users/<user_uuid>`
  * GET `0.1/groups/<group_uuid>/users`
  * GET `0.1/users/<user_uuid>/groups`

* A new resource has been added to assign a Policies to Groups

  * PUT `0.1/groups/<group_uuid>/policies/<policy_uuid>`
  * DELETE `0.1/groups/<group_uuid>/policies/<policy_uuid>`
  * GET `0.1/groups/<group_uuid>/policies`

* The URL to create users with a token has been changed

  * POST `0.1/users/register`

* The user creation url now needs a token and does not require a password anymore

  * POST `0.1/users`

* All DELETE on association now return 204 if the resources are not associated but both exists

  * DELETE `0.1/users/<user_uuid>/policies/<policy_uuid>`
  * DELETE `0.1/groups/<group_uuid>/policies/<policy_uuid>`
  * DELETE `0.1/groups/<group_uuid>/users/<user_uuid>`
  * DELETE `0.1/tenants/<tenant_uuid>/users/<user_uuid>`

* A UUID can be supplied when creating a user

* A new URL has been added to change a user's password

  * PUT `0.1/users/<user_uuid>/password`

## 17.16

* A new resource has been added to manage Tenants

  * POST `0.1/tenants`
  * GET `0.1/tenants`
  * GET `0.1/tenants/<tenant_uuid>`
  * DELETE `0.1/tenants/<tenant_uuid>`

* A new resource has been added to assign policies to users

  * PUT `0.1/users/<user_uuid>/policies/<policy_uuid>`
  * DELETE `0.1/users/<user_uuid>/policies/<policy_uuid>`
  * GET `0.1/users/<user_uuid>/policies/`

* A new resource has been added to assign users to tenants

  * PUT ``0.1/tenants/<tenant_uuid>/users/<user_uuid>``
  * DELETE ``0.1/tenants/<tenant_uuid>/users/<user_uuid>``
  * GET ``0.1/tenants/<tenant_uuid>/users/``
  * GET ``0.1/users/<user_uuid>/tenants/``

* A new ressource has been added to manage Groups

  * POST `0.1/groups`
  * GET `0.1/groups`
  * GET `0.1/groups/<group_uuid>`
  * PUT `0.1/groups/<group_uuid>`
  * DELETE `0.1/groups/<group_uuid>`

## 17.15

* A new resource has been added to manage Users

  * POST `0.1/users`
  * GET `0.1/users`
  * GET `0.1/users/<user_uuid>`
  * DELETE `0.1/users/<user_uuid>`

## 17.02

* A new resource has been added to manage ACL policies

  * POST `/0.1/polices`
  * GET `/0.1/policies`
  * GET `/0.1/policies/<policy_uuid>`
  * PUT `/0.1/policies/<policy_uuid>`
  * DELETE `/0.1/policies/<policy_uuid>`
  * PUT `/0.1/policies/<policy_uuid>/acl_templates/<template>`
  * DELETE `/0.1/policies/<policy_uuid>/acl_templates/<template>`

## 16.16

* The token data in the response of POST and GET on `/0.1/token` now include the following new fields

  * utc_expires_at
  * utc_issued_at
  * xivo_uuid

## 16.02

* POST `/0.1/token`, field `expiration`: only integers are accepted, floats are now invalid.
* Experimental backend `ldap_user_voicemail` has been removed.
* New backend `ldap_user` has been added.

## 15.19

* POST `/0.1/token` do not accept anymore argument `backend_args`

## 15.17

* New backend `ldap_user_voicemail` has been added. **WARNING** this backend is **EXPERIMENTAL**.

## 15.16

* HEAD and GET now take a new `scope` query string argument to check ACLs
* Backend interface method `get_acls` is now named `get_consul_acls`
* Backend interface method `get_acls` now returns a list of ACLs
* HEAD and GET can now return a `403` if an ACL access is denied

## 15.15

* POST `/0.1/token` accept new argument `backend_args`
* Signature of backend method `get_ids()` has a new argument `args`
* New method `get_acls` for backend has been added
* New backend `service` has been added
