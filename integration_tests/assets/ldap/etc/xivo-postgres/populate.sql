INSERT INTO "tenant" (uuid) VALUES ((SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid)) ON CONFLICT DO NOTHING;
INSERT INTO "entity" ("name", "displayname", "tenant_uuid", "description") VALUES ('default', 'Default', (SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid), '');
INSERT INTO "func_key_template" (private) VALUES (TRUE);
INSERT INTO "userfeatures" (uuid, firstname, email, description, func_key_private_template_id, entityid, tenant_uuid)
VALUES
(1, 'Alice', 'awonderland@wazo-auth.com', '', 1, (SELECT id FROM entity ORDER BY id DESC LIMIT 1), (SELECT uuid FROM auth_tenant WHERE uuid = parent_uuid));
