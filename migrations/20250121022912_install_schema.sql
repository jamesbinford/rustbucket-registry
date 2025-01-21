-- Add migration script here
CREATE TABLE IF NOT EXISTS admin_users (
id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
username TEXT NOT NULL UNIQUE,
password_hash TEXT NOT NULL,
role TEXT NOT NULL,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rustbucket_registrations (
id UUID PRIMARY KEY,
token TEXT NOT NULL,
hostname TEXT NOT NULL,
instance_name TEXT,
version TEXT NOT NULL,
status TEXT NOT NULL,
created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
approved_at TIMESTAMPTZ,
admin_notes TEXT
);

-- Initial admin user (optional)
INSERT INTO admin_users (username, password_hash, role)
VALUES ('admin', 'change-this-password-hash', 'admin')
ON CONFLICT DO NOTHING;-- Add migration script here
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rustbucket_registrations (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL,
    hostname TEXT NOT NULL,
    instance_name TEXT,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    admin_notes TEXT
);

-- Initial admin user (optional)
INSERT INTO admin_users (username, password_hash, role)
VALUES ('admin', 'change-this-password-hash', 'admin')
ON CONFLICT DO NOTHING;-- Add migration script here
CREATE TABLE IF NOT EXISTS admin_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS rustbucket_registrations (
    id UUID PRIMARY KEY,
    token TEXT NOT NULL,
    hostname TEXT NOT NULL,
    instance_name TEXT,
    version TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    approved_at TIMESTAMPTZ,
    admin_notes TEXT
);

-- Initial admin user (optional)
INSERT INTO admin_users (username, password_hash, role)
VALUES ('admin', 'change-this-password-hash', 'admin')
ON CONFLICT DO NOTHING;