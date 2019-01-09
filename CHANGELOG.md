Changelog
=========

19.02
-----

* Old method `get_ids` for backend has been removed
* GET on `/users/password/reset` does not delete the current password anymore


19.01
-----

* The backend `xivo_admin` has been removed


18.14
-----

* The backend option in `POST /tokens` is now optional. The default value is `wazo_user`
* The backend `xivo_service` has been removed


18.13
-----

* `POST /init` can now take the purpose attribute
* A user now has a `purpose` property
* The following URLs have been deprecated. Use `Wazo-Tenant` header instead:

  * GET `0.1/tenants/<tenant_uuid>/policies`
  * GET `0.1/tenants/<tenant_uuid>/users`
  * GET `0.1/users/<user_uuid>/tenants`


18.06
-----

* Groups now have a tenant_uuid

  * POST on /groups will create the group in the token's user tenant_uuid or in the specified Wazo-Tenant
  * add tenant filtering on the following endpoints

    * GET, PUT, DELETE `/groups/<group_uuid>/users`
    * GET /users/<user_uuid>/groups
    * GET, PUT, DELETE `/groups/<group_uuid>`
    * GET /groups


18.05
-----

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


18.04
-----

* Add the `uuid` field on POST `0.1/tenants`
* A user now has a tenant_uuid. It is either:

  * the creator's tenant_uuid
  * the specified Wazo-Tenant header's value

* A tenant now has a parent_uuid which is the tenant_uuid of the tenant above this tenant in the hierarchy.
* The GET /tenants only return tenants that are below the tenant_uuid of the user doing the request or specified by Wazo-Tenant
* The GET /users only return user from the same tenant as the requester or Wazo-Tenant
* The recurse parameter has been added on /users to include users from all sub-tenants


18.03
-----

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


18.02
-----

* A new resource has been added to trigger a new email confirmation email

  * GET `0.1/users/<user_uuid>/emails/<email_uuid>/confirm`

* Add the "metadata" field on the token body

  * POST `0.1/token`
  * GET `0.1/token/<token_uuid>`


18.01
-----

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


17.17
-----

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


17.16
-----

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


17.15
-----

* A new resource has been added to manage Users

  * POST `0.1/users`
  * GET `0.1/users`
  * GET `0.1/users/<user_uuid>`
  * DELETE `0.1/users/<user_uuid>`


17.02
-----

* A new resource has been added to manage ACL policies

  * POST `/0.1/polices`
  * GET `/0.1/policies`
  * GET `/0.1/policies/<policy_uuid>`
  * PUT `/0.1/policies/<policy_uuid>`
  * DELETE `/0.1/policies/<policy_uuid>`
  * PUT `/0.1/policies/<policy_uuid>/acl_templates/<template>`
  * DELETE `/0.1/policies/<policy_uuid>/acl_templates/<template>`


16.16
-----

* The token data in the response of POST and GET on `/0.1/token` now include the following new fields

  * utc_expires_at
  * utc_issued_at
  * xivo_uuid


16.02
-----

* POST `/0.1/token`, field `expiration`: only integers are accepted, floats are now invalid.
* Experimental backend `ldap_user_voicemail` has been removed.
* New backend `ldap_user` has been added.


15.19
-----

* POST `/0.1/token` do not accept anymore argument `backend_args`


15.17
-----

* New backend `ldap_user_voicemail` has been added. **WARNING** this backend is **EXPERIMENTAL**.


15.16
-----

* HEAD and GET now take a new `scope` query string argument to check ACLs
* Backend interface method `get_acls` is now named `get_consul_acls`
* Backend interface method `get_acls` now returns a list of ACLs
* HEAD and GET can now return a `403` if an ACL access is denied


15.15
-----

* POST `/0.1/token` accept new argument `backend_args`
* Signature of backend method `get_ids()` has a new argument `args`
* New method `get_acls` for backend has been added
* New backend `service` has been added
