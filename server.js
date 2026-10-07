require("dotenv").config();

const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();

const PORT = process.env.PORT || 10000;

const DATABASE_URL = process.env.DATABASE_URL;

const PAYSTACK_SECRET_KEY =
    process.env.PAYSTACK_SECRET_KEY;

const JWT_SECRET =
    process.env.JWT_SECRET;

const FRONTEND_URL =
    process.env.FRONTEND_URL || "*";

if (!DATABASE_URL) {
    console.error("DATABASE_URL is missing.");
    process.exit(1);
}

if (!PAYSTACK_SECRET_KEY) {
    console.error("PAYSTACK_SECRET_KEY is missing.");
    process.exit(1);
}

if (!JWT_SECRET) {
    console.error("JWT_SECRET is missing.");
    process.exit(1);
}


/* ========================================================
   DATABASE
======================================================== */

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl: {
        rejectUnauthorized: false
    },

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000
});


pool.on("error", (error) => {
    console.error("PostgreSQL pool error:", error);
});


/* ========================================================
   PAYSTACK WEBHOOK MUST COME BEFORE express.json()
======================================================== */

app.post(
    "/api/paystack/webhook",

    express.raw({
        type: "application/json"
    }),

    async (req, res) => {

        try {

            const signature =
                req.headers["x-paystack-signature"];

            if (!signature) {
                return res
                    .status(401)
                    .send("Missing signature");
            }

            const hash =
                crypto
                    .createHmac(
                        "sha512",
                        PAYSTACK_SECRET_KEY
                    )
                    .update(req.body)
                    .digest("hex");

            if (hash !== signature) {
                return res
                    .status(401)
                    .send("Invalid signature");
            }

            const event =
                JSON.parse(
                    req.body.toString()
                );

            if (
                event.event ===
                "charge.success"
            ) {

                const transaction =
                    event.data;

                const reference =
                    transaction.reference;

                const client =
                    await pool.connect();

                try {

                    await client.query(
                        "BEGIN"
                    );

                    const orderResult =
                        await client.query(
                            `
                            SELECT
                                o.*,
                                b.price_pesewas
                            FROM orders o
                            JOIN bundles b
                              ON b.id = o.bundle_id
                            WHERE o.paystack_reference = $1
                            FOR UPDATE
                            `,
                            [reference]
                        );

                    if (
                        orderResult.rowCount === 0
                    ) {

                        await client.query(
                            "ROLLBACK"
                        );

                        return res.sendStatus(
                            200
                        );
                    }

                    const order =
                        orderResult.rows[0];

                    const expectedAmount =
                        Number(
                            order.price_pesewas
                        );

                    const receivedAmount =
                        Number(
                            transaction.amount
                        );

                    if (
                        transaction.status ===
                            "success" &&
                        expectedAmount ===
                            receivedAmount
                    ) {

                        await client.query(
                            `
                            UPDATE orders
                            SET
                                payment_status = 'PAID',
                                paystack_transaction_id = $1,
                                paid_at = NOW(),
                                updated_at = NOW()
                            WHERE id = $2
                            `,
                            [
                                String(
                                    transaction.id
                                ),
                                order.id
                            ]
                        );

                        await client.query(
                            `
                            UPDATE payments
                            SET
                                status = 'success',
                                transaction_id = $1,
                                channel = $2,
                                gateway_response = $3,
                                raw_response = $4,
                                updated_at = NOW()
                            WHERE reference = $5
                            `,
                            [
                                String(
                                    transaction.id
                                ),
                                transaction.channel ||
                                    null,
                                transaction.gateway_response ||
                                    null,
                                transaction,
                                reference
                            ]
                        );
                    }

                    await client.query(
                        "COMMIT"
                    );

                } catch (error) {

                    await client.query(
                        "ROLLBACK"
                    );

                    throw error;

                } finally {

                    client.release();

                }

            }

            return res.sendStatus(200);

        } catch (error) {

            console.error(
                "Paystack webhook error:",
                error
            );

            return res.sendStatus(500);
        }
    }
);


/* ========================================================
   MIDDLEWARE
======================================================== */

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);


app.use(
    cors({
        origin:
            FRONTEND_URL === "*"
                ? true
                : FRONTEND_URL,

        credentials: true
    })
);


app.use(
    express.json({
        limit: "1mb"
    })
);


const authLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        max: 30,
        standardHeaders: true,
        legacyHeaders: false
    });


const paymentLimiter =
    rateLimit({
        windowMs: 10 * 60 * 1000,
        max: 30,
        standardHeaders: true,
        legacyHeaders: false
    });


/* ========================================================
   HELPERS
======================================================== */

function createToken(user) {

    return jwt.sign(
        {
            id: user.id,
            email: user.email,
            role: user.role
        },

        JWT_SECRET,

        {
            expiresIn: "7d"
        }
    );
}


function normalizeEmail(email) {

    return String(email)
        .trim()
        .toLowerCase();
}


function normalizePhone(phone) {

    return String(phone)
        .trim()
        .replace(/\s+/g, "");
}


function validGhanaPhone(phone) {

    return /^(0\d{9}|233\d{9})$/.test(
        phone
    );
}


function generateReference() {

    return (
        "CD_" +
        Date.now() +
        "_" +
        crypto
            .randomBytes(6)
            .toString("hex")
    );
}


/* ========================================================
   AUTH MIDDLEWARE
======================================================== */

function authenticate(req, res, next) {

    const header =
        req.headers.authorization;

    if (
        !header ||
        !header.startsWith("Bearer ")
    ) {

        return res.status(401).json({
            success: false,
            error: "Authentication required."
        });
    }

    const token =
        header.substring(7);

    try {

        const decoded =
            jwt.verify(
                token,
                JWT_SECRET
            );

        req.user = decoded;

        next();

    } catch {

        return res.status(401).json({
            success: false,
            error: "Invalid or expired token."
        });
    }
}


function adminOnly(req, res, next) {

    if (
        !req.user ||
        req.user.role !== "ADMIN"
    ) {

        return res.status(403).json({
            success: false,
            error: "Administrator access required."
        });
    }

    next();
}


/* ========================================================
   HEALTH
======================================================== */

app.get("/", async (req, res) => {

    try {

        await pool.query(
            "SELECT 1"
        );

        res.json({
            status: "ok",
            app: "CheapData",
            database: "connected",
            paystack: "configured",
            fulfillment: "supplier integration pending"
        });

    } catch (error) {

        res.status(500).json({
            status: "error",
            database: "disconnected"
        });
    }
});


/* ========================================================
   REGISTER
======================================================== */

app.post(
    "/api/auth/register",
    authLimiter,
    async (req, res) => {

        try {

            const {
                name,
                email,
                phone,
                password
            } = req.body;

            if (
                !name ||
                !email ||
                !password
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Name, email and password are required."
                });
            }

            if (
                String(password).length < 8
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Password must contain at least 8 characters."
                });
            }

            const normalizedEmail =
                normalizeEmail(email);

            const existing =
                await pool.query(
                    `
                    SELECT id
                    FROM users
                    WHERE email = $1
                    `,
                    [normalizedEmail]
                );

            if (existing.rowCount > 0) {

                return res.status(409).json({
                    success: false,
                    error:
                        "An account with this email already exists."
                });
            }

            const passwordHash =
                await bcrypt.hash(
                    password,
                    12
                );

            const result =
                await pool.query(
                    `
                    INSERT INTO users
                    (
                        name,
                        email,
                        phone,
                        password_hash
                    )
                    VALUES
                    ($1,$2,$3,$4)
                    RETURNING
                        id,
                        name,
                        email,
                        phone,
                        role,
                        created_at
                    `,
                    [
                        String(name).trim(),
                        normalizedEmail,
                        phone
                            ? normalizePhone(phone)
                            : null,
                        passwordHash
                    ]
                );

            const user =
                result.rows[0];

            const token =
                createToken(user);

            res.status(201).json({
                success: true,
                token,
                user
            });

        } catch (error) {

            console.error(
                "Register error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Registration failed."
            });
        }
    }
);


/* ========================================================
   LOGIN
======================================================== */

app.post(
    "/api/auth/login",
    authLimiter,
    async (req, res) => {

        try {

            const {
                email,
                password
            } = req.body;

            if (!email || !password) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Email and password are required."
                });
            }

            const normalizedEmail =
                normalizeEmail(email);

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM users
                    WHERE email = $1
                    `,
                    [normalizedEmail]
                );

            if (
                result.rowCount === 0
            ) {

                return res.status(401).json({
                    success: false,
                    error:
                        "Invalid email or password."
                });
            }

            const user =
                result.rows[0];

            const valid =
                await bcrypt.compare(
                    password,
                    user.password_hash
                );

            if (!valid) {

                return res.status(401).json({
                    success: false,
                    error:
                        "Invalid email or password."
                });
            }

            const safeUser = {
                id: user.id,
                name: user.name,
                email: user.email,
                phone: user.phone,
                role: user.role,
                created_at:
                    user.created_at
            };

            const token =
                createToken(
                    safeUser
                );

            res.json({
                success: true,
                token,
                user: safeUser
            });

        } catch (error) {

            console.error(
                "Login error:",
                error
            );

            res.status(500).json({
                success: false,
                error:
                    "Login failed."
            });
        }
    }
);


/* ========================================================
   CURRENT USER
======================================================== */

app.get(
    "/api/auth/me",
    authenticate,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        name,
                        email,
                        phone,
                        role,
                        created_at
                    FROM users
                    WHERE id = $1
                    `,
                    [req.user.id]
                );

            if (
                result.rowCount === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error: "User not found."
                });
            }

            res.json({
                success: true,
                user: result.rows[0]
            });

        } catch (error) {

            res.status(500).json({
                success: false,
                error:
                    "Unable to load account."
            });
        }
    }
);


/* ========================================================
   BUNDLES
======================================================== */

app.get(
    "/api/bundles",
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        id,
                        code,
                        network,
                        data_amount,
                        validity,
                        price_pesewas,
                        currency
                    FROM bundles
                    WHERE active = TRUE
                    ORDER BY
                        network,
                        price_pesewas
                    `
                );

            res.json({
                success: true,
                bundles:
                    result.rows
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                success: false,
                error:
                    "Unable to load bundles."
            });
        }
    }
);


/* ========================================================
   INITIALIZE PAYMENT
======================================================== */

app.post(
    "/api/payments/initialize",
    authenticate,
    paymentLimiter,
    async (req, res) => {

        const client =
            await pool.connect();

        try {

            const {
                bundleId,
                phone
            } = req.body;

            if (
                !bundleId ||
                !phone
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Bundle and recipient phone are required."
                });
            }

            const recipientPhone =
                normalizePhone(phone);

            if (
                !validGhanaPhone(
                    recipientPhone
                )
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Enter a valid Ghana phone number."
                });
            }

            const bundleResult =
                await client.query(
                    `
                    SELECT *
                    FROM bundles
                    WHERE id = $1
                      AND active = TRUE
                    `,
                    [bundleId]
                );

            if (
                bundleResult.rowCount === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Bundle not found."
                });
            }

            const bundle =
                bundleResult.rows[0];

            const reference =
                generateReference();

            const amount =
                Number(
                    bundle.price_pesewas
                );

            await client.query(
                "BEGIN"
            );

            const orderResult =
                await client.query(
                    `
                    INSERT INTO                     orders (
                        user_id,
                        bundle_id,
                        recipient_phone,
                        amount_pesewas,
                        currency,
                        payment_status,
                        fulfillment_status,
                        paystack_reference
                    )
                    VALUES (
                        $1,
                        $2,
                        $3,
                        $4,
                        'GHS',
                        'PENDING',
                        'PENDING',
                        $5
                    )
                    RETURNING *
                    `,
                    [
                        req.user.id,
                        bundle.id,
                        recipientPhone,
                        amount,
                        reference
                    ]
                );

            const order =
                orderResult.rows[0];

            /*
             * Initialize transaction with Paystack.
             * IMPORTANT:
             * The amount comes from our database,
             * not from the customer's request.
             */

            const paystackResponse =
                await fetch(
                    "https://api.paystack.co/transaction/initialize",
                    {
                        method: "POST",

                        headers: {
                            Authorization:
                                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
                            "Content-Type":
                                "application/json"
                        },

                        body: JSON.stringify({
                            email: req.user.email,
                            amount: amount,
                            currency: "GHS",
                            reference: reference,

                            metadata: {
                                order_id:
                                    order.id,
                                user_id:
                                    req.user.id,
                                bundle_id:
                                    bundle.id,
                                recipient_phone:
                                    recipientPhone
                            }
                        })
                    }
                );

            const paystackData =
                await paystackResponse.json();

            if (
                !paystackResponse.ok ||
                !paystackData.status
            ) {

                await client.query(
                    `
                    UPDATE orders
                    SET payment_status = 'FAILED',
                        failure_reason = $1
                    WHERE id = $2
                    `,
                    [
                        paystackData.message ||
                            "Paystack initialization failed.",
                        order.id
                    ]
                );

                await client.query(
                    "ROLLBACK"
                );

                return res.status(502).json({
                    success: false,
                    error:
                        paystackData.message ||
                        "Unable to initialize payment."
                });
            }

            /*
             * Save payment record.
             */

            await client.query(
                `
                INSERT INTO payments (
                    order_id,
                    provider,
                    reference,
                    amount_pesewas,
                    currency,
                    status,
                    raw_response
                )
                VALUES (
                    $1,
                    'PAYSTACK',
                    $2,
                    $3,
                    'GHS',
                    'INITIALIZED',
                    $4
                )
                `,
                [
                    order.id,
                    reference,
                    amount,
                    JSON.stringify(
                        paystackData
                    )
                ]
            );

            await client.query(
                "COMMIT"
            );

            return res.json({
                success: true,

                order: {
                    id:
                        order.id,
                    reference:
                        reference,
                    amount:
                        amount,
                    currency:
                        "GHS",
                    bundle:
                        bundle.data_amount,
                    network:
                        bundle.network,
                    recipient_phone:
                        recipientPhone
                },

                payment: {
                    authorization_url:
                        paystackData.data.authorization_url,

                    access_code:
                        paystackData.data.access_code,

                    reference:
                        paystackData.data.reference
                }
            });

        } catch (error) {

            try {
                await client.query(
                    "ROLLBACK"
                );
            } catch (_) {}

            console.error(
                "Payment initialization error:",
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    "Payment initialization failed."
            });

        } finally {

            client.release();
        }
    }
);


/* ========================================================
   VERIFY PAYMENT
======================================================== */

app.get(
    "/api/payments/verify/:reference",
    authenticate,
    async (req, res) => {

        const reference =
            req.params.reference;

        if (!reference) {

            return res.status(400).json({
                success: false,
                error:
                    "Payment reference is required."
            });
        }

        const client =
            await pool.connect();

        try {

            /*
             * Find the order first.
             * This prevents a user from verifying
             * another user's payment.
             */

            const orderResult =
                await client.query(
                    `
                    SELECT
                        o.*,
                        p.id AS payment_id
                    FROM orders o
                    LEFT JOIN payments p
                        ON p.order_id = o.id
                    WHERE o.paystack_reference = $1
                      AND o.user_id = $2
                    LIMIT 1
                    `,
                    [
                        reference,
                        req.user.id
                    ]
                );

            if (
                orderResult.rowCount === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Payment order not found."
                });
            }

            const order =
                orderResult.rows[0];

            /*
             * Ask Paystack for the actual
             * transaction status.
             */

            const paystackResponse =
                await fetch(
                    `https://api.paystack.co/transaction/verify/${encodeURIComponent(reference)}`,
                    {
                        method: "GET",

                        headers: {
                            Authorization:
                                `Bearer ${process.env.PAYSTACK_SECRET_KEY}`
                        }
                    }
                );

            const paystackData =
                await paystackResponse.json();

            if (
                !paystackResponse.ok ||
                !paystackData.status
            ) {

                return res.status(502).json({
                    success: false,
                    error:
                        paystackData.message ||
                        "Unable to verify payment."
                });
            }

            const transaction =
                paystackData.data;

            /*
             * Make sure the amount paid is exactly
             * the amount stored for the order.
             */

            const paidAmount =
                Number(
                    transaction.amount
                );

            const expectedAmount =
                Number(
                    order.amount_pesewas
                );

            if (
                paidAmount !==
                expectedAmount
            ) {

                await client.query(
                    `
                    UPDATE orders
                    SET payment_status = 'FAILED',
                        failure_reason = $1
                    WHERE id = $2
                    `,
                    [
                        "Payment amount does not match order amount.",
                        order.id
                    ]
                );

                return res.status(400).json({
                    success: false,
                    error:
                        "Payment amount does not match the order."
                });
            }

            /*
             * Payment successful.
             */

            if (
                transaction.status ===
                "success"
            ) {

                await client.query(
                    "BEGIN"
                );

                await client.query(
                    `
                    UPDATE orders
                    SET
                        payment_status = 'PAID',
                        payment_transaction_id = $1,
                        paid_at = COALESCE(
                            paid_at,
                            NOW()
                        ),
                        updated_at = NOW()
                    WHERE id = $2
                    `,
                    [
                        String(
                            transaction.id
                        ),
                        order.id
                    ]
                );

                await client.query(
                    `
                    UPDATE payments
                    SET
                        transaction_id = $1,
                        status = 'SUCCESS',
                        channel = $2,
                        gateway_response = $3,
                        raw_response = $4,
                        updated_at = NOW()
                    WHERE reference = $5
                    `,
                    [
                        String(
                            transaction.id
                        ),
                        transaction.channel ||
                            null,
                        transaction.gateway_response ||
                            null,
                        JSON.stringify(
                            paystackData
                        ),
                        reference
                    ]
                );

                await client.query(
                    "COMMIT"
                );

                return res.json({
                    success: true,

                    paid: true,

                    message:
                        "Payment confirmed successfully.",

                    order: {
                        id:
                            order.id,

                        reference:
                            reference,

                        payment_status:
                            "PAID",

                        fulfillment_status:
                            order.fulfillment_status
                    }
                });
            }

            /*
             * Payment has not succeeded yet.
             */

            return res.json({
                success: true,

                paid: false,

                status:
                    transaction.status,

                message:
                    "Payment has not been completed."
            });

        } catch (error) {

            try {
                await client.query(
                    "ROLLBACK"
                );
            } catch (_) {}

            console.error(
                "Payment verification error:",
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    "Payment verification failed."
            });

        } finally {

            client.release();
        }
    }
);


/* ========================================================
   CUSTOMER ORDERS
======================================================== */

app.get(
    "/api/orders",
    authenticate,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        o.id,
                        o.recipient_phone,
                        o.amount_pesewas,
                        o.currency,
                        o.payment_status,
                        o.fulfillment_status,
                        o.paystack_reference,
                        o.supplier_reference,
                        o.failure_reason,
                        o.created_at,
                        o.paid_at,

                        b.network,
                        b.data_amount,
                        b.validity

                    FROM orders o

                    INNER JOIN bundles b
                        ON b.id = o.bundle_id

                    WHERE o.user_id = $1

                    ORDER BY
                        o.created_at DESC
                    `,
                    [req.user.id]
                );

            return res.json({
                success: true,
                orders:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Orders error:",
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    "Unable to load orders."
            });
        }
    }
);


/* ========================================================
   ADMIN - VIEW ALL ORDERS
======================================================== */

app.get(
    "/api/admin/orders",
    authenticate,
    adminOnly,
    async (req, res) => {

        try {

            const result =
                await pool.query(
                    `
                    SELECT
                        o.*,

                        u.name AS customer_name,
                        u.email AS customer_email,

                        b.network,
                        b.data_amount,
                        b.validity

                    FROM orders o

                    INNER JOIN users u
                        ON u.id = o.user_id

                    INNER JOIN bundles b
                        ON b.id = o.bundle_id

                    ORDER BY
                        o.created_at DESC
                    `
                );

            return res.json({
                success: true,
                orders:
                    result.rows
            });

        } catch (error) {

            console.error(
                "Admin orders error:",
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    "Unable to load admin orders."
            });
        }
    }
);


/* ========================================================
   ADMIN - UPDATE FULFILLMENT
======================================================== */

app.patch(
    "/api/admin/orders/:id/fulfillment",
    authenticate,
    adminOnly,
    async (req, res) => {

        try {

            const {
                status,
                supplierReference,
                failureReason
            } = req.body;

            const allowedStatuses = [
                "PENDING",
                "SUBMITTED",
                "DELIVERED",
                "FAILED"
            ];

            if (
                !allowedStatuses.includes(
                    status
                )
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Invalid fulfillment status."
                });
            }

            if (
                status === "DELIVERED" &&
                !supplierReference
            ) {

                return res.status(400).json({
                    success: false,
                    error:
                        "Supplier reference is required when marking an order as delivered."
                });
            }

            const result =
                await pool.query(
                    `
                    UPDATE orders

                    SET
                        fulfillment_status = $1,

                        supplier_reference =
                            CASE
                                WHEN $1 = 'DELIVERED'
                                THEN $2
                                ELSE supplier_reference
                            END,

                        failure_reason =
                            CASE
                                WHEN $1 = 'FAILED'
                                THEN $3
                                ELSE failure_reason
                            END,

                        delivered_at =
                            CASE
                                WHEN $1 = 'DELIVERED'
                                THEN NOW()
                                ELSE delivered_at
                            END,

                        updated_at = NOW()

                    WHERE id = $4

                    RETURNING *
                    `,
                    [
                        status,
                        supplierReference ||
                            null,
                        failureReason ||
                            null,
                        req.params.id
                    ]
                );

            if (
                result.rowCount === 0
            ) {

                return res.status(404).json({
                    success: false,
                    error:
                        "Order not found."
                });
            }

            return res.json({
                success: true,

                order:
                    result.rows[0]
            });

        } catch (error) {

            console.error(
                "Fulfillment update error:",
                error
            );

            return res.status(500).json({
                success: false,
                error:
                    "Unable to update fulfillment."
            });
        }
    }
);


/* ========================================================
   404 ROUTE
======================================================== */

app.use(
    (req, res) => {

        return res.status(404).json({
            success: false,
            error:
                "Route not found"
        });
    }
);


/* ========================================================
   GLOBAL ERROR HANDLER
======================================================== */

app.use(
    (error, req, res, next) => {

        console.error(
            "Unhandled server error:",
            error
        );

        if (res.headersSent) {
            return next(error);
        }

        return res.status(500).json({
            success: false,
            error:
                "Internal server error."
        });
    }
);


/* ========================================================
   START SERVER
======================================================== */

app.listen(
    PORT,
    () => {

        console.log(
            `CheapData backend running on port ${PORT}`
        );
    }
);
