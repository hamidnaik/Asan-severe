require('dotenv').config();

const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');;
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();

const PORT = process.env.PORT || 3000;

// ===============================
// بررسی تنظیمات ضروری
// ===============================
if (!process.env.DATABASE_URL) {
    console.error('❌ DATABASE_URL تنظیم نشده است.');
}

if (!process.env.JWT_SECRET) {
    console.error('❌ JWT_SECRET تنظیم نشده است.');
}

// ===============================
// اتصال به PostgreSQL
// ===============================
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,

    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false
});

// ===============================
// Middleware
// ===============================
app.use(express.json());
app.use(cookieParser());

app.use(
    cors({
        origin: true,
        credentials: true
    })
);

// ===============================
// صفحه اصلی
// ===============================
app.get('/', (req, res) => {
    res.json({
        success: true,
        message: '🇦🇫 بازار افغانستان فعال است',
        name: 'Bazar Afghanistan',
        port: PORT
    });
});

// ===============================
// بررسی سلامت API
// ===============================
app.get('/api/health', async (req, res) => {
    try {
        await pool.query('SELECT 1');

        res.json({
            success: true,
            message: 'API و PostgreSQL فعال هستند'
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            error: 'اتصال به PostgreSQL برقرار نیست'
        });
    }
});

// ===============================
// ساخت Token
// ===============================
function createToken(user) {
    return jwt.sign(
        {
            id: user.id,
            role: user.role
        },
        process.env.JWT_SECRET,
        {
            expiresIn: '24h'
        }
    );
}

// ===============================
// ارسال پاسخ ورود
// ===============================
function sendAuthResponse(res, user) {
    const token = createToken(user);

    res.cookie('token', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: process.env.NODE_ENV === 'production'
            ? 'none'
            : 'lax',
        maxAge: 24 * 60 * 60 * 1000
    });

    res.json({
        success: true,
        message: 'ورود موفق',
        token,
        user: {
            id: user.id,
            username: user.username,
            email: user.email,
            role: user.role,
            is_verified: user.is_verified
        }
    });
}

// ===============================
// احراز هویت
// ===============================
const authenticate = async (req, res, next) => {
    let token = req.cookies.token;

    // پشتیبانی از Authorization Bearer
    if (!token && req.headers.authorization) {
        const parts = req.headers.authorization.split(' ');

        if (parts.length === 2 && parts[0] === 'Bearer') {
            token = parts[1];
        }
    }

    if (!token) {
        return res.status(401).json({
            error: 'احراز هویت نشده'
        });
    }

    try {
        const decoded = jwt.verify(
            token,
            process.env.JWT_SECRET
        );

        const result = await pool.query(
            `SELECT id, username, email, role, is_verified
             FROM users
             WHERE id = $1`,
            [decoded.id]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'کاربر یافت نشد'
            });
        }

        req.user = result.rows[0];

        next();

    } catch (error) {
        return res.status(401).json({
            error: 'توکن نامعتبر یا منقضی شده است'
        });
    }
};

// ===============================
// تعیین سطح دسترسی
// ===============================
const authorize = (...roles) => {
    return (req, res, next) => {

        if (!req.user) {
            return res.status(401).json({
                error: 'احراز هویت نشده'
            });
        }

        if (!roles.includes(req.user.role)) {
            return res.status(403).json({
                error: 'دسترسی غیرمجاز'
            });
        }

        next();
    };
};

// ===============================
// ساخت مدیر اولیه
// ===============================
async function setupInitialAdmin() {

    const adminUsername =
        process.env.ADMIN_USERNAME || 'admin';

    const adminPassword =
        process.env.ADMIN_PASSWORD || 'Admin@1234';

    const adminEmail =
        process.env.ADMIN_EMAIL || 'admin@example.com';

    try {

        const hashedPassword = await bcrypt.hash(
            adminPassword,
            10
        );

        await pool.query(
            `INSERT INTO users
            (username, email, password_hash, role, is_verified)
            VALUES ($1, $2, $3, 'admin', true)
            ON CONFLICT (username) DO NOTHING`,
            [
                adminUsername,
                adminEmail,
                hashedPassword
            ]
        );

        console.log('✅ مدیر اولیه بررسی/ایجاد شد.');

    } catch (error) {

        console.error(
            '❌ خطا در ساخت مدیر:',
            error.message
        );
    }
}

// ==================================================
// AUTH - ثبت نام
// ==================================================
app.post('/api/auth/register', async (req, res) => {

    const {
        username,
        email,
        password,
        role = 'customer'
    } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({
            error: 'نام کاربری، ایمیل و رمز عبور الزامی است'
        });
    }

    // کاربر معمولی نمی‌تواند خودش admin بسازد
    if (!['customer', 'seller'].includes(role)) {
        return res.status(400).json({
            error: 'نوع حساب نامعتبر است'
        });
    }

    try {

        const hashedPassword = await bcrypt.hash(
            password,
            10
        );

        const result = await pool.query(
            `INSERT INTO users
            (username, email, password_hash, role)
            VALUES ($1, $2, $3, $4)
            RETURNING id, username, email, role, is_verified`,
            [
                username,
                email,
                hashedPassword,
                role
            ]
        );

        res.status(201).json({
            success: true,
            message: 'ثبت نام موفق',
            user: result.rows[0]
        });

    } catch (error) {

        if (error.code === '23505') {
            return res.status(400).json({
                error: 'نام کاربری یا ایمیل قبلاً استفاده شده است'
            });
        }

        console.error(error);

        res.status(500).json({
            error: 'خطای سرور'
        });
    }
});

// ==================================================
// AUTH - ورود
// ==================================================
app.post('/api/auth/login', async (req, res) => {

    const {
        username,
        password
    } = req.body;

    if (!username || !password) {
        return res.status(400).json({
            error: 'نام کاربری/ایمیل و رمز عبور الزامی است'
        });
    }

    try {

        const result = await pool.query(
            `SELECT *
             FROM users
             WHERE username = $1
                OR email = $1
             LIMIT 1`,
            [username]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                error: 'نام کاربری یا رمز عبور نادرست است'
            });
        }

        const user = result.rows[0];

        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                error: 'نام کاربری یا رمز عبور نادرست است'
            });
        }

        sendAuthResponse(res, user);

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: 'خطای سرور'
        });
    }
});

// ==================================================
// AUTH - کاربر فعلی
// ==================================================
app.get(
    '/api/auth/me',
    authenticate,
    (req, res) => {

        res.json({
            success: true,
            user: req.user
        });
    }
);

// ==================================================
// AUTH - خروج
// ==================================================
app.post('/api/auth/logout', (req, res) => {

    res.clearCookie('token');

    res.json({
        success: true,
        message: 'با موفقیت خارج شدید'
    });
});

// ==================================================
// PRODUCTS - ثبت محصول
// ==================================================
app.post(
    '/api/products',
    authenticate,
    authorize('seller', 'admin'),
    async (req, res) => {

        const {
            name,
            description = '',
            price,
            stock_quantity = 0
        } = req.body;

        if (!name || price === undefined) {
            return res.status(400).json({
                error: 'نام و قیمت محصول الزامی است'
            });
        }

        if (
            req.user.role === 'seller' &&
            !req.user.is_verified
        ) {
            return res.status(403).json({
                error: 'حساب فروشندگی شما هنوز تأیید نشده است'
            });
        }

        const sellerId =
            req.user.role === 'admin'
                ? req.body.seller_id || req.user.id
                : req.user.id;

        try {

            const result = await pool.query(
                `INSERT INTO products
                (seller_id, name, description, price, stock_quantity)
                VALUES ($1, $2, $3, $4, $5)
                RETURNING *`,
                [
                    sellerId,
                    name,
                    description,
                    price,
                    stock_quantity
                ]
            );

            await pool.query(
                `INSERT INTO audit_logs
                (user_id, action, details)
                VALUES ($1, $2, $3)`,
                [
                    req.user.id,
                    'CREATE_PRODUCT',
                    JSON.stringify({
                        product_id: result.rows[0].id
                    })
                ]
            );

            res.status(201).json({
                success: true,
                product: result.rows[0]
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });
        }
    }
);

// ==================================================
// PRODUCTS - لیست محصولات
// ==================================================
app.get('/api/products', async (req, res) => {

    try {

        const result = await pool.query(
            `SELECT
                p.*,
                u.username AS seller_name
             FROM products p
             JOIN users u
               ON p.seller_id = u.id
             WHERE p.stock_quantity > 0
             ORDER BY p.created_at DESC`
        );

        res.json({
            success: true,
            products: result.rows
        });

    } catch (error) {

        console.error(error);

        res.status(500).json({
            error: error.message
        });
    }
});

// ==================================================
// ORDERS - ثبت سفارش
// ==================================================
app.post(
    '/api/orders',
    authenticate,
    authorize('customer'),
    async (req, res) => {

        const { items } = req.body;

        if (
            !Array.isArray(items) ||
            items.length === 0
        ) {
            return res.status(400).json({
                error: 'سبد خرید خالی است'
            });
        }

        const client = await pool.connect();

        try {

            await client.query('BEGIN');

            let total = 0;

            const orderItems = [];

            for (const item of items) {

                if (
                    !item.product_id ||
                    !Number.isInteger(item.quantity) ||
                    item.quantity <= 0
                ) {
                    throw new Error(
                        'اطلاعات محصول یا تعداد نامعتبر است'
                    );
                }

                const productResult =
                    await client.query(
                        `SELECT *
                         FROM products
                         WHERE id = $1
                         FOR UPDATE`,
                        [item.product_id]
                    );

                if (productResult.rows.length === 0) {
                    throw new Error(
                        `محصول ${item.product_id} یافت نشد`
                    );
                }

                const product =
                    productResult.rows[0];

                if (
                    product.stock_quantity <
                    item.quantity
                ) {
                    throw new Error(
                        `موجودی ${product.name} کافی نیست`
                    );
                }

                await client.query(
                    `UPDATE products
                     SET stock_quantity =
                         stock_quantity - $1
                     WHERE id = $2`,
                    [
                        item.quantity,
                        item.product_id
                    ]
                );

                total +=
                    Number(product.price) *
                    item.quantity;

                orderItems.push({
                    product_id: item.product_id,
                    quantity: item.quantity,
                    price_at_time: product.price
                });
            }

            const orderResult =
                await client.query(
                    `INSERT INTO orders
                    (customer_id, total_amount)
                    VALUES ($1, $2)
                    RETURNING *`,
                    [
                        req.user.id,
                        total
                    ]
                );

            const orderId =
                orderResult.rows[0].id;

            for (const item of orderItems) {

                await client.query(
                    `INSERT INTO order_items
                    (order_id, product_id, quantity, price_at_time)
                    VALUES ($1, $2, $3, $4)`,
                    [
                        orderId,
                        item.product_id,
                        item.quantity,
                        item.price_at_time
                    ]
                );
            }

            await client.query('COMMIT');

            res.status(201).json({
                success: true,
                message: 'سفارش با موفقیت ثبت شد',
                order_id: orderId,
                total
            });

        } catch (error) {

            await client.query('ROLLBACK');

            console.error(error);

            res.status(400).json({
                error: error.message
            });

        } finally {

            client.release();
        }
    }
);

// ==================================================
// ADMIN - تأیید فروشنده
// ==================================================
app.put(
    '/api/admin/verify-seller/:userId',
    authenticate,
    authorize('admin'),
    async (req, res) => {

        const { userId } = req.params;

        try {

            const result = await pool.query(
                `UPDATE users
                 SET is_verified = true
                 WHERE id = $1
                   AND role = 'seller'
                 RETURNING id, username, email, role, is_verified`,
                [userId]
            );

            if (result.rows.length === 0) {
                return res.status(404).json({
                    error: 'فروشنده یافت نشد'
                });
            }

            await pool.query(
                `INSERT INTO audit_logs
                (user_id, action, details)
                VALUES ($1, $2, $3)`,
                [
                    req.user.id,
                    'VERIFY_SELLER',
                    JSON.stringify({
                        seller_id: userId
                    })
                ]
            );

            res.json({
                success: true,
                message: 'فروشنده تأیید شد',
                seller: result.rows[0]
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });
        }
    }
);

// ==================================================
// ADMIN - گزارش سفارشات
// ==================================================
app.get(
    '/api/admin/reports',
    authenticate,
    authorize('admin'),
    async (req, res) => {

        try {

            const result = await pool.query(`
                SELECT
                    o.id,
                    o.total_amount,
                    o.status,
                    o.created_at,
                    u.username AS customer_name,
                    json_agg(
                        json_build_object(
                            'product_name', p.name,
                            'quantity', oi.quantity,
                            'price', oi.price_at_time
                        )
                    ) AS items
                FROM orders o
                JOIN users u
                    ON o.customer_id = u.id
                JOIN order_items oi
                    ON o.id = oi.order_id
                JOIN products p
                    ON oi.product_id = p.id
                GROUP BY
                    o.id,
                    u.username
                ORDER BY
                    o.created_at DESC
            `);

            res.json({
                success: true,
                reports: result.rows
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });
        }
    }
);

// ==================================================
// ADMIN - لیست کاربران
// ==================================================
app.get(
    '/api/admin/users',
    authenticate,
    authorize('admin'),
    async (req, res) => {

        try {

            const result = await pool.query(
                `SELECT
                    id,
                    username,
                    email,
                    role,
                    is_verified,
                    created_at
                 FROM users
                 ORDER BY created_at DESC`
            );

            res.json({
                success: true,
                users: result.rows
            });

        } catch (error) {

            console.error(error);

            res.status(500).json({
                error: error.message
            });
        }
    }
);

// ==================================================
// راه‌اندازی نهایی سرور
// ==================================================
async function startServer() {

    try {

        if (!process.env.DATABASE_URL) {
            throw new Error(
                'DATABASE_URL در متغیرهای محیطی وجود ندارد'
            );
        }

        if (!process.env.JWT_SECRET) {
            throw new Error(
                'JWT_SECRET در متغیرهای محیطی وجود ندارد'
            );
        }

        await pool.query('SELECT 1');

        console.log('✅ PostgreSQL متصل شد');

        await setupInitialAdmin();

        app.listen(
            PORT,
            '0.0.0.0',
            () => {

                console.log(
                    `🇦🇫 بازار افغانستان روی پورت ${PORT} اجرا شد`
                );

                console.log(
                    `🚀 Bazar Afghanistan API is running on port ${PORT}`
                );
            }
        );

    } catch (error) {

        console.error(
            '❌ سرور اجرا نشد:',
            error.message
        );

        process.exit(1);
    }
}

startServer();