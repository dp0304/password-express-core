-- SPDX-License-Identifier: Apache-2.0
-- "Lure store" demo database for AI Pass (design doc §5.4 / §14.1 P0 walkthrough).
-- Raw customer data (with e-mail addresses) is never exposed to AI tools; only the
-- aggregated view analytics.subscription_daily is allowlisted in the resource config,
-- and the connecting role is read-only.
-- 演示数据库：原始客户表包含邮箱，AI 只能通过白名单视图读取聚合数据，连接账号只读。

CREATE SCHEMA IF NOT EXISTS shop;
CREATE SCHEMA IF NOT EXISTS analytics;

CREATE TABLE shop.customers (
    customer_id  bigserial PRIMARY KEY,
    email        text NOT NULL UNIQUE,
    full_name    text NOT NULL,
    country      text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE shop.subscriptions (
    subscription_id bigserial PRIMARY KEY,
    customer_id     bigint NOT NULL REFERENCES shop.customers(customer_id),
    plan            text NOT NULL CHECK (plan IN ('basic', 'pro', 'team')),
    started_on      date NOT NULL,
    canceled_on     date,
    price_cents     integer NOT NULL
);

INSERT INTO shop.customers (email, full_name, country) VALUES
    ('ada@example.com',   'Ada Lovelace',     'GB'),
    ('grace@example.com', 'Grace Hopper',     'US'),
    ('linus@example.com', 'Linus Torvalds',   'FI'),
    ('yukihiro@example.com', 'Yukihiro Matsumoto', 'JP'),
    ('mei@example.com',   'Mei Chen',         'CN');

INSERT INTO shop.subscriptions (customer_id, plan, started_on, canceled_on, price_cents) VALUES
    (1, 'pro',   DATE '2026-10-01', NULL,              1900),
    (2, 'basic', DATE '2026-10-01', NULL,               900),
    (3, 'team',  DATE '2026-10-02', NULL,              4900),
    (4, 'pro',   DATE '2026-10-02', DATE '2026-10-20', 1900),
    (5, 'basic', DATE '2026-10-03', NULL,               900);

-- Aggregated, e-mail free view the AI may read.
CREATE VIEW analytics.subscription_daily AS
SELECT d::date                         AS day,
       s.plan                          AS plan,
       count(*)::bigint                AS subscriptions,
       sum(s.price_cents)::bigint      AS mrr_cents
FROM generate_series(DATE '2026-10-01', DATE '2026-10-31', INTERVAL '1 day') AS d
JOIN shop.subscriptions s
  ON s.started_on <= d::date AND (s.canceled_on IS NULL OR s.canceled_on > d::date)
GROUP BY 1, 2;

-- Read-only login used by the executor. The password is set by the operator, e.g.
--   ALTER ROLE lure_readonly PASSWORD '<generated>';
-- and stored only in the AI Pass vault.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'lure_readonly') THEN
        CREATE ROLE lure_readonly LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
    END IF;
END $$;
ALTER ROLE lure_readonly SET default_transaction_read_only = on;
GRANT USAGE ON SCHEMA analytics TO lure_readonly;
GRANT SELECT ON analytics.subscription_daily TO lure_readonly;
-- The raw tables stay private: the view owner (not lure_readonly) reads them.
REVOKE ALL ON SCHEMA shop FROM PUBLIC;
