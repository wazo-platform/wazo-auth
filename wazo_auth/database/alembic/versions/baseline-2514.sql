-- PostgreSQL database dump

-- Dumped from database version 13.18 (Debian 13.18-0+deb11u1)
-- Dumped by pg_dump version 13.18 (Debian 13.18-0+deb11u1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

-- Name: auth_access; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_access (
    id integer NOT NULL,
    access text NOT NULL
);

-- Name: auth_acl_template_id_seq; Type: SEQUENCE; Schema: public; Owner: -

CREATE SEQUENCE public.auth_acl_template_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Name: auth_acl_template_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -

ALTER SEQUENCE public.auth_acl_template_id_seq OWNED BY public.auth_access.id;

-- Name: auth_address; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_address (
    id integer NOT NULL,
    line_1 text,
    line_2 text,
    city text,
    state text,
    zip_code text,
    country text,
    tenant_uuid character varying(38) NOT NULL
);

-- Name: auth_address_id_seq; Type: SEQUENCE; Schema: public; Owner: -

CREATE SEQUENCE public.auth_address_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;

-- Name: auth_address_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -

ALTER SEQUENCE public.auth_address_id_seq OWNED BY public.auth_address.id;

-- Name: auth_email; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_email (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    address text NOT NULL,
    confirmed boolean NOT NULL,
    main boolean NOT NULL,
    user_uuid character varying(38) NOT NULL
);

-- Name: auth_external_auth_config; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_external_auth_config (
    type_uuid character varying(36) NOT NULL,
    tenant_uuid character varying(38) NOT NULL,
    data text NOT NULL
);

-- Name: auth_external_auth_type; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_external_auth_type (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    enabled boolean
);

-- Name: auth_group; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_group (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    name text NOT NULL,
    tenant_uuid character varying(38) NOT NULL,
    system_managed boolean DEFAULT false NOT NULL,
    slug character varying(80) NOT NULL
);

-- Name: auth_group_policy; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_group_policy (
    group_uuid character varying(38) NOT NULL,
    policy_uuid character varying(38) NOT NULL
);

-- Name: auth_ldap_config; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_ldap_config (
    tenant_uuid character varying(38) NOT NULL,
    host character varying(512) NOT NULL,
    port integer NOT NULL,
    protocol_version smallint,
    protocol_security text,
    bind_dn character varying(256),
    bind_password text,
    user_base_dn character varying(256) NOT NULL,
    user_login_attribute character varying(64),
    user_email_attribute character varying(64),
    search_filters text,
    CONSTRAINT auth_ldap_config_protocol_security_check CHECK ((protocol_security = ANY (ARRAY['ldaps'::text, 'tls'::text])))
);

-- Name: auth_policy; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_policy (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(80) NOT NULL,
    description text,
    tenant_uuid character varying(38) NOT NULL,
    config_managed boolean DEFAULT false,
    slug character varying(80) NOT NULL,
    shared boolean DEFAULT false NOT NULL
);

-- Name: auth_policy_access; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_policy_access (
    policy_uuid character varying(38) NOT NULL,
    access_id integer NOT NULL
);

-- Name: auth_refresh_token; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_refresh_token (
    uuid character varying(36) DEFAULT public.uuid_generate_v4() NOT NULL,
    client_id text,
    user_uuid character varying(36),
    backend text,
    login text,
    user_agent text,
    remote_addr text,
    created_at timestamp with time zone DEFAULT now(),
    mobile boolean DEFAULT false NOT NULL,
    metadata json DEFAULT '{}'::json NOT NULL
);

-- Name: auth_saml_config; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_saml_config (
    tenant_uuid character varying(38) NOT NULL,
    domain_uuid character varying(38) NOT NULL,
    entity_id character varying(512) NOT NULL,
    idp_metadata xml NOT NULL,
    acs_url character varying(512) NOT NULL
);

-- Name: auth_saml_pysaml2_cache; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_saml_pysaml2_cache (
    name_id character varying(512) NOT NULL,
    entity_id character varying(1024) NOT NULL,
    info text NOT NULL,
    not_on_or_after integer NOT NULL
);

-- Name: auth_saml_session; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_saml_session (
    request_id character varying(40) NOT NULL,
    session_id character varying(22) NOT NULL,
    redirect_url character varying(512) NOT NULL,
    domain character varying(512) NOT NULL,
    relay_state character varying(100) NOT NULL,
    login character varying(512),
    start_time timestamp with time zone DEFAULT now(),
    saml_name_id text,
    refresh_token_uuid character varying(36)
);

-- Name: auth_session; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_session (
    uuid character varying(36) DEFAULT public.uuid_generate_v4() NOT NULL,
    mobile boolean NOT NULL,
    tenant_uuid character varying(38) NOT NULL
);

-- Name: auth_tenant; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_tenant (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    name text,
    phone text,
    contact_uuid character varying(38),
    parent_uuid character varying(38) NOT NULL,
    slug character varying(10) NOT NULL,
    default_authentication_method text DEFAULT 'native'::text NOT NULL
);

-- Name: auth_tenant_domain; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_tenant_domain (
    uuid character varying(36) DEFAULT public.uuid_generate_v4() NOT NULL,
    tenant_uuid character varying(38) NOT NULL,
    name character varying(253) NOT NULL
);

-- Name: auth_token; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_token (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    auth_id text NOT NULL,
    pbx_user_uuid character varying(36),
    xivo_uuid character varying(38),
    issued_t integer,
    expire_t integer,
    metadata text,
    session_uuid character varying(36) NOT NULL,
    user_agent text DEFAULT ''::text,
    remote_addr text DEFAULT ''::text,
    acl text[] DEFAULT '{}'::text[] NOT NULL,
    refresh_token_uuid character varying(36)
);

-- Name: auth_user; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_user (
    uuid character varying(38) DEFAULT public.uuid_generate_v4() NOT NULL,
    username character varying(256),
    password_hash text,
    password_salt bytea,
    firstname text,
    lastname text,
    enabled boolean DEFAULT true,
    tenant_uuid character varying(38) NOT NULL,
    purpose text NOT NULL,
    authentication_method text DEFAULT 'default'::text NOT NULL,
    CONSTRAINT auth_user_purpose_check CHECK ((purpose = ANY (ARRAY['user'::text, 'internal'::text, 'external_api'::text])))
);

-- Name: auth_user_external_auth; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_user_external_auth (
    user_uuid character varying(38) NOT NULL,
    external_auth_type_uuid character varying(38) NOT NULL,
    data text NOT NULL
);

-- Name: auth_user_group; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_user_group (
    group_uuid character varying(38) NOT NULL,
    user_uuid character varying(38) NOT NULL
);

-- Name: auth_user_policy; Type: TABLE; Schema: public; Owner: -

CREATE TABLE public.auth_user_policy (
    user_uuid character varying(38) NOT NULL,
    policy_uuid character varying(38) NOT NULL
);

-- Name: auth_access id; Type: DEFAULT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_access ALTER COLUMN id SET DEFAULT nextval('public.auth_acl_template_id_seq'::regclass);

-- Name: auth_address id; Type: DEFAULT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_address ALTER COLUMN id SET DEFAULT nextval('public.auth_address_id_seq'::regclass);

-- Data for Name: auth_access; Type: TABLE DATA; Schema: public; Owner: -

INSERT INTO public.auth_access(access) VALUES ('#');

-- Data for Name: auth_tenant; Type: TABLE DATA; Schema: public; Owner: -

INSERT INTO public.auth_tenant
SELECT master_uuid, 'master', NULL, NULL, master_uuid, 'master', 'native'
FROM (SELECT public.uuid_generate_v4() AS master_uuid) AS master_tenant;

-- Data for Name: auth_address; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_email; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_external_auth_config; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_external_auth_type; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_group; Type: TABLE DATA; Schema: public; Owner: -

INSERT INTO public.auth_group
SELECT
    public.uuid_generate_v4(),
    'wazo-all-users-tenant-' || master_uuid,
    master_uuid,
    true,
    'wazo-all-users-tenant-' || master_uuid
FROM (
    SELECT uuid AS master_uuid FROM public.auth_tenant WHERE name = 'master'
) AS master_tenant;

-- Data for Name: auth_group_policy; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_ldap_config; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_policy; Type: TABLE DATA; Schema: public; Owner: -

INSERT INTO public.auth_policy VALUES (
    public.uuid_generate_v4(),
    'wazo_default_master_user_policy',
    'Default Wazo policy for the "master" user

Do not modify this policy, it can be modified in future Wazo upgrades
',
    (SELECT uuid FROM public.auth_tenant WHERE name = 'master'),
    false,
    'wazo_default_master_user_policy',
    false
);

-- Data for Name: auth_policy_access; Type: TABLE DATA; Schema: public; Owner: -

INSERT INTO public.auth_policy_access VALUES (
    (SELECT uuid FROM public.auth_policy WHERE name = 'wazo_default_master_user_policy'),
    (SELECT id FROM public.auth_access WHERE access = '#')
);

-- Data for Name: auth_refresh_token; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_saml_config; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_saml_pysaml2_cache; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_saml_session; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_session; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_tenant_domain; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_token; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_user; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_user_external_auth; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_user_group; Type: TABLE DATA; Schema: public; Owner: -

-- Data for Name: auth_user_policy; Type: TABLE DATA; Schema: public; Owner: -

-- Name: auth_acl_template_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -

SELECT pg_catalog.setval('public.auth_acl_template_id_seq', 3, true);

-- Name: auth_address_id_seq; Type: SEQUENCE SET; Schema: public; Owner: -

SELECT pg_catalog.setval('public.auth_address_id_seq', 1, false);

-- Name: auth_access auth_access_access; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_access
    ADD CONSTRAINT auth_access_access UNIQUE (access);

-- Name: auth_access auth_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_access
    ADD CONSTRAINT auth_access_pkey PRIMARY KEY (id);

-- Name: auth_address auth_address_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_address
    ADD CONSTRAINT auth_address_pkey PRIMARY KEY (id);

-- Name: auth_email auth_email_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_email
    ADD CONSTRAINT auth_email_pkey PRIMARY KEY (uuid);

-- Name: auth_external_auth_config auth_external_auth_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_external_auth_config
    ADD CONSTRAINT auth_external_auth_config_pkey PRIMARY KEY (type_uuid, tenant_uuid);

-- Name: auth_external_auth_type auth_external_auth_type_name_key; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_external_auth_type
    ADD CONSTRAINT auth_external_auth_type_name_key UNIQUE (name);

-- Name: auth_external_auth_type auth_external_auth_type_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_external_auth_type
    ADD CONSTRAINT auth_external_auth_type_pkey PRIMARY KEY (uuid);

-- Name: auth_user_external_auth auth_external_user_type_auth_constraint; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_external_auth
    ADD CONSTRAINT auth_external_user_type_auth_constraint UNIQUE (user_uuid, external_auth_type_uuid);

-- Name: auth_group auth_group_name_tenant; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_name_tenant UNIQUE (name, tenant_uuid);

-- Name: auth_group auth_group_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_pkey PRIMARY KEY (uuid);

-- Name: auth_group_policy auth_group_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group_policy
    ADD CONSTRAINT auth_group_policy_pkey PRIMARY KEY (group_uuid, policy_uuid);

-- Name: auth_ldap_config auth_ldap_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_ldap_config
    ADD CONSTRAINT auth_ldap_config_pkey PRIMARY KEY (tenant_uuid);

-- Name: auth_policy_access auth_policy_access_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy_access
    ADD CONSTRAINT auth_policy_access_pkey PRIMARY KEY (policy_uuid, access_id);

-- Name: auth_policy auth_policy_name_tenant; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy
    ADD CONSTRAINT auth_policy_name_tenant UNIQUE (name, tenant_uuid);

-- Name: auth_policy auth_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy
    ADD CONSTRAINT auth_policy_pkey PRIMARY KEY (uuid);

-- Name: auth_refresh_token auth_refresh_token_client_id_user_uuid; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_refresh_token
    ADD CONSTRAINT auth_refresh_token_client_id_user_uuid UNIQUE (client_id, user_uuid);

-- Name: auth_refresh_token auth_refresh_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_refresh_token
    ADD CONSTRAINT auth_refresh_token_pkey PRIMARY KEY (uuid);

-- Name: auth_saml_config auth_saml_config_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_config
    ADD CONSTRAINT auth_saml_config_pkey PRIMARY KEY (tenant_uuid, domain_uuid);

-- Name: auth_saml_pysaml2_cache auth_saml_pysaml2_cache_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_pysaml2_cache
    ADD CONSTRAINT auth_saml_pysaml2_cache_pkey PRIMARY KEY (name_id, entity_id);

-- Name: auth_saml_session auth_saml_session_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_session
    ADD CONSTRAINT auth_saml_session_pkey PRIMARY KEY (request_id, session_id);

-- Name: auth_session auth_session_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_session
    ADD CONSTRAINT auth_session_pkey PRIMARY KEY (uuid);

-- Name: auth_tenant_domain auth_tenant_domain_name_key; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant_domain
    ADD CONSTRAINT auth_tenant_domain_name_key UNIQUE (name);

-- Name: auth_tenant_domain auth_tenant_domain_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant_domain
    ADD CONSTRAINT auth_tenant_domain_pkey PRIMARY KEY (uuid);

-- Name: auth_tenant auth_tenant_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant
    ADD CONSTRAINT auth_tenant_pkey PRIMARY KEY (uuid);

-- Name: auth_tenant auth_tenant_slug_key; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant
    ADD CONSTRAINT auth_tenant_slug_key UNIQUE (slug);

-- Name: auth_token auth_token_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_token
    ADD CONSTRAINT auth_token_pkey PRIMARY KEY (uuid);

-- Name: auth_user_group auth_user_group_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_group
    ADD CONSTRAINT auth_user_group_pkey PRIMARY KEY (group_uuid, user_uuid);

-- Name: auth_user auth_user_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_pkey PRIMARY KEY (uuid);

-- Name: auth_user_policy auth_user_policy_pkey; Type: CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_policy
    ADD CONSTRAINT auth_user_policy_pkey PRIMARY KEY (user_uuid, policy_uuid);

-- Name: auth_address__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_address__idx__tenant_uuid ON public.auth_address USING btree (tenant_uuid);

-- Name: auth_email__idx__user_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_email__idx__user_uuid ON public.auth_email USING btree (user_uuid);

-- Name: auth_email_address_key; Type: INDEX; Schema: public; Owner: -

CREATE UNIQUE INDEX auth_email_address_key ON public.auth_email USING btree (lower(address));

-- Name: auth_external_auth_config__idx__type_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_external_auth_config__idx__type_uuid ON public.auth_external_auth_config USING btree (type_uuid);

-- Name: auth_group__idx__slug; Type: INDEX; Schema: public; Owner: -

CREATE UNIQUE INDEX auth_group__idx__slug ON public.auth_group USING btree (lower((slug)::text), tenant_uuid);

-- Name: auth_group__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_group__idx__tenant_uuid ON public.auth_group USING btree (tenant_uuid);

-- Name: auth_policy__idx__slug; Type: INDEX; Schema: public; Owner: -

CREATE UNIQUE INDEX auth_policy__idx__slug ON public.auth_policy USING btree (lower((slug)::text), tenant_uuid);

-- Name: auth_policy__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_policy__idx__tenant_uuid ON public.auth_policy USING btree (tenant_uuid);

-- Name: auth_refresh_token__idx__user_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_refresh_token__idx__user_uuid ON public.auth_refresh_token USING btree (user_uuid);

-- Name: auth_session__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_session__idx__tenant_uuid ON public.auth_session USING btree (tenant_uuid);

-- Name: auth_tenant__idx__contact_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_tenant__idx__contact_uuid ON public.auth_tenant USING btree (contact_uuid);

-- Name: auth_tenant__idx__parent_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_tenant__idx__parent_uuid ON public.auth_tenant USING btree (parent_uuid);

-- Name: auth_tenant_domain__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_tenant_domain__idx__tenant_uuid ON public.auth_tenant_domain USING btree (tenant_uuid);

-- Name: auth_token__idx__session_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_token__idx__session_uuid ON public.auth_token USING btree (session_uuid);

-- Name: auth_user__idx__tenant_uuid; Type: INDEX; Schema: public; Owner: -

CREATE INDEX auth_user__idx__tenant_uuid ON public.auth_user USING btree (tenant_uuid);

-- Name: auth_user_username_key; Type: INDEX; Schema: public; Owner: -

CREATE UNIQUE INDEX auth_user_username_key ON public.auth_user USING btree (lower((username)::text));

-- Name: auth_address auth_address_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_address
    ADD CONSTRAINT auth_address_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_email auth_email_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_email
    ADD CONSTRAINT auth_email_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.auth_user(uuid) ON DELETE CASCADE;

-- Name: auth_external_auth_config auth_external_auth_config_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_external_auth_config
    ADD CONSTRAINT auth_external_auth_config_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_external_auth_config auth_external_auth_config_type_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_external_auth_config
    ADD CONSTRAINT auth_external_auth_config_type_uuid_fkey FOREIGN KEY (type_uuid) REFERENCES public.auth_external_auth_type(uuid) ON DELETE CASCADE;

-- Name: auth_group_policy auth_group_policy_group_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group_policy
    ADD CONSTRAINT auth_group_policy_group_uuid_fkey FOREIGN KEY (group_uuid) REFERENCES public.auth_group(uuid) ON DELETE CASCADE;

-- Name: auth_group_policy auth_group_policy_policy_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group_policy
    ADD CONSTRAINT auth_group_policy_policy_uuid_fkey FOREIGN KEY (policy_uuid) REFERENCES public.auth_policy(uuid) ON DELETE CASCADE;

-- Name: auth_group auth_group_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_group
    ADD CONSTRAINT auth_group_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_ldap_config auth_ldap_config_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_ldap_config
    ADD CONSTRAINT auth_ldap_config_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_policy_access auth_policy_access_access_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy_access
    ADD CONSTRAINT auth_policy_access_access_id_fkey FOREIGN KEY (access_id) REFERENCES public.auth_access(id) ON DELETE CASCADE;

-- Name: auth_policy_access auth_policy_access_policy_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy_access
    ADD CONSTRAINT auth_policy_access_policy_uuid_fkey FOREIGN KEY (policy_uuid) REFERENCES public.auth_policy(uuid) ON DELETE CASCADE;

-- Name: auth_policy auth_policy_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_policy
    ADD CONSTRAINT auth_policy_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_refresh_token auth_refresh_token_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_refresh_token
    ADD CONSTRAINT auth_refresh_token_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.auth_user(uuid) ON DELETE CASCADE;

-- Name: auth_saml_config auth_saml_config_domain_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_config
    ADD CONSTRAINT auth_saml_config_domain_uuid_fkey FOREIGN KEY (domain_uuid) REFERENCES public.auth_tenant_domain(uuid) ON DELETE CASCADE;

-- Name: auth_saml_config auth_saml_config_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_config
    ADD CONSTRAINT auth_saml_config_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_saml_session auth_saml_session_refresh_token_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_saml_session
    ADD CONSTRAINT auth_saml_session_refresh_token_uuid_fkey FOREIGN KEY (refresh_token_uuid) REFERENCES public.auth_refresh_token(uuid) ON DELETE SET NULL;

-- Name: auth_session auth_session_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_session
    ADD CONSTRAINT auth_session_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_tenant auth_tenant_contact_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant
    ADD CONSTRAINT auth_tenant_contact_uuid_fkey FOREIGN KEY (contact_uuid) REFERENCES public.auth_user(uuid) ON DELETE SET NULL;

-- Name: auth_tenant_domain auth_tenant_domain_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant_domain
    ADD CONSTRAINT auth_tenant_domain_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- Name: auth_tenant auth_tenant_parent_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_tenant
    ADD CONSTRAINT auth_tenant_parent_uuid_fkey FOREIGN KEY (parent_uuid) REFERENCES public.auth_tenant(uuid);

-- Name: auth_token auth_token_refresh_token_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_token
    ADD CONSTRAINT auth_token_refresh_token_uuid_fkey FOREIGN KEY (refresh_token_uuid) REFERENCES public.auth_refresh_token(uuid) ON DELETE SET NULL;

-- Name: auth_token auth_token_session_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_token
    ADD CONSTRAINT auth_token_session_uuid_fkey FOREIGN KEY (session_uuid) REFERENCES public.auth_session(uuid) ON DELETE CASCADE;

-- Name: auth_user_external_auth auth_user_external_auth_external_auth_type_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_external_auth
    ADD CONSTRAINT auth_user_external_auth_external_auth_type_uuid_fkey FOREIGN KEY (external_auth_type_uuid) REFERENCES public.auth_external_auth_type(uuid) ON DELETE CASCADE;

-- Name: auth_user_external_auth auth_user_external_auth_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_external_auth
    ADD CONSTRAINT auth_user_external_auth_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.auth_user(uuid) ON DELETE CASCADE;

-- Name: auth_user_group auth_user_group_group_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_group
    ADD CONSTRAINT auth_user_group_group_uuid_fkey FOREIGN KEY (group_uuid) REFERENCES public.auth_group(uuid) ON DELETE CASCADE;

-- Name: auth_user_group auth_user_group_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_group
    ADD CONSTRAINT auth_user_group_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.auth_user(uuid) ON DELETE CASCADE;

-- Name: auth_user_policy auth_user_policy_policy_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_policy
    ADD CONSTRAINT auth_user_policy_policy_uuid_fkey FOREIGN KEY (policy_uuid) REFERENCES public.auth_policy(uuid) ON DELETE CASCADE;

-- Name: auth_user_policy auth_user_policy_user_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user_policy
    ADD CONSTRAINT auth_user_policy_user_uuid_fkey FOREIGN KEY (user_uuid) REFERENCES public.auth_user(uuid) ON DELETE CASCADE;

-- Name: auth_user auth_user_tenant_uuid_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -

ALTER TABLE ONLY public.auth_user
    ADD CONSTRAINT auth_user_tenant_uuid_fkey FOREIGN KEY (tenant_uuid) REFERENCES public.auth_tenant(uuid) ON DELETE CASCADE;

-- PostgreSQL database dump complete
