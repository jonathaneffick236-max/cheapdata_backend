CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- =========================================================
-- USERS
-- =========================================================

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    name VARCHAR(120) NOT NULL,

    email VARCHAR(255) NOT NULL UNIQUE,

    phone VARCHAR(30),

    password_hash TEXT NOT NULL,

    role VARCHAR(20) NOT NULL DEFAULT 'CUSTOMER'
        CHECK (role IN ('CUSTOMER', 'ADMIN')),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_email
ON users(email);


-- =========================================================
-- BUNDLES
-- =========================================================

CREATE TABLE IF NOT EXISTS bundles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    code VARCHAR(80) NOT NULL UNIQUE,

    network VARCHAR(50) NOT NULL,

    data_amount VARCHAR(50) NOT NULL,

    validity VARCHAR(80) NOT NULL,

    price_pesewas INTEGER NOT NULL
        CHECK (price_pesewas > 0),

    currency VARCHAR(10) NOT NULL DEFAULT 'GHS',

    active BOOLEAN NOT NULL DEFAULT TRUE,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_bundles_network
ON bundles(network);

CREATE INDEX IF NOT EXISTS idx_bundles_active
ON bundles(active);


-- =========================================================
-- ORDERS
-- =========================================================

CREATE TABLE IF NOT EXISTS orders (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    user_id UUID NOT NULL
        REFERENCES users(id)
        ON DELETE RESTRICT,

    bundle_id UUID NOT NULL
        REFERENCES bundles(id)
        ON DELETE RESTRICT,

    recipient_phone VARCHAR(30) NOT NULL,

    amount_pesewas INTEGER NOT NULL
        CHECK (amount_pesewas > 0),

    currency VARCHAR(10) NOT NULL DEFAULT 'GHS',

    payment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            payment_status IN (
                'PENDING',
                'PAID',
                'FAILED',
                'CANCELLED'
            )
        ),

    fulfillment_status VARCHAR(30) NOT NULL DEFAULT 'PENDING'
        CHECK (
            fulfillment_status IN (
                'PENDING',
                'SUBMITTED',
                'DELIVERED',
                'FAILED'
            )
        ),

    paystack_reference VARCHAR(100) UNIQUE,

    paystack_transaction_id VARCHAR(100),

    supplier_reference VARCHAR(150),

    failure_reason TEXT,

    paid_at TIMESTAMPTZ,

    delivered_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_orders_user
ON orders(user_id);

CREATE INDEX IF NOT EXISTS idx_orders_payment_status
ON orders(payment_status);

CREATE INDEX IF NOT EXISTS idx_orders_created
ON orders(created_at DESC);


-- =========================================================
-- PAYMENTS
-- =========================================================

CREATE TABLE IF NOT EXISTS payments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    order_id UUID NOT NULL
        REFERENCES orders(id)
        ON DELETE RESTRICT,

    provider VARCHAR(30) NOT NULL DEFAULT 'PAYSTACK',

    reference VARCHAR(100) NOT NULL UNIQUE,

    transaction_id VARCHAR(100),

    amount_pesewas INTEGER NOT NULL,

    currency VARCHAR(10) NOT NULL,

    status VARCHAR(40) NOT NULL DEFAULT 'PENDING',

    channel VARCHAR(80),

    gateway_response TEXT,

    raw_response JSONB,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_payments_order
ON payments(order_id);

CREATE INDEX IF NOT EXISTS idx_payments_reference
ON payments(reference);


-- =========================================================
-- SEED BUNDLES
-- =========================================================

INSERT INTO bundles
(code, network, data_amount, validity, price_pesewas)
VALUES

('MTN_1GB_7D',
 'MTN',
 '1GB',
 '7 Days',
 500),

('MTN_2GB_7D',
 'MTN',
 '2GB',
 '7 Days',
 900),

('MTN_5GB_30D',
 'MTN',
 '5GB',
 '30 Days',
 2000),

('MTN_10GB_30D',
 'MTN',
 '10GB',
 '30 Days',
 3800),

('TELECEL_1GB_7D',
 'Telecel',
 '1GB',
 '7 Days',
 500),

('TELECEL_2GB_7D',
 'Telecel',
 '2GB',
 '7 Days',
 900),

('TELECEL_5GB_30D',
 'Telecel',
 '5GB',
 '30 Days',
 1900),

('AIRTELTIGO_1GB_7D',
 'AirtelTigo',
 '1GB',
 '7 Days',
 500),

('AIRTELTIGO_2GB_7D',
 'AirtelTigo',
 '2GB',
 '7 Days',
 900),

('AIRTELTIGO_5GB_30D',
 'AirtelTigo',
 '5GB',
 '30 Days',
 1900)

ON CONFLICT (code) DO NOTHING;


-- =========================================================
-- ADMIN
-- =========================================================
--
-- Do NOT insert a plaintext password.
--
-- First register normally through the app.
-- Then find the user's UUID:
--
-- SELECT id,email,role FROM users;
--
-- Then promote that account:
--
-- UPDATE users
-- SET role = 'ADMIN'
-- WHERE email = 'your-email@example.com';
--
