INSERT INTO "entity" (name, displayname, description) VALUES ('xivotest', 'xivotest', '');

INSERT INTO "accesswebservice" (name, login, passwd, obj, description) VALUES ('admin', 'admin', 'proformatique', '', '');

INSERT INTO "context" (name, displayname, contexttype, description, entity)
VALUES
('default', 'Default', 'internal', '', 'xivotest'),
('from-extern', 'Incalls', 'incall', '', 'xivotest'),
('to-extern', 'Outcalls', 'incall', '', 'xivotest');

INSERT INTO "contextinclude" (context, include) VALUES ('default', 'to-extern');

INSERT INTO "contextnumbers" (context, type, numberbeg, numberend, didlength)
VALUES
('default', 'user', '1000', '1999', 0),
('from-extern', 'incall', '1000', '4999', 0);

INSERT INTO "voicemail" (context, mailbox, email) VALUES ('default', '1001', 'awonderland@xivo-auth.com');
INSERT INTO "func_key_template" (private) VALUES (TRUE);
INSERT INTO "userfeatures" (uuid, firstname, voicemailid, description, func_key_private_template_id, entityid)
VALUES
(1, 'Alice', currval('voicemail_uniqueid_seq'), '', currval('func_key_template_id_seq'), currval('entity_id_seq'));

CREATE DATABASE xivotemplate TEMPLATE asterisk;
