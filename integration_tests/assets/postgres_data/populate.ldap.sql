INSERT INTO "tenant" (uuid) VALUES ((SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid)) ON CONFLICT DO NOTHING;
INSERT INTO "func_key_template" (tenant_uuid, private) VALUES ((SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid), TRUE);
INSERT INTO "userfeatures" (uuid, firstname, email, description, func_key_private_template_id, tenant_uuid)
VALUES
(1, 'Alice', 'awonderland@wazo-auth.com', '', 1, (SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid));
