Changelog
=========

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
