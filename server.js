require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// اتصال به PostgreSQL
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Middlewareها
app.use(express.json());
app.use(cookieParser());
app.use(cors({ origin: 'http://localhost:3000', credentials: true }));

// ------------------- توابع کمکی (Middleware احراز هویت) -------------------
const authenticate = async (req, res, next) => {
    const token = req.cookies.token;
    if (!token) return res.status(401).json({ error: 'احراز هویت نشده' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const result = await pool.query('SELECT id, username, email, role, is_verified FROM users WHERE id = $1', [decoded.id]);
        if (result.rows.length === 0) throw new Error('کاربر یافت نشد');
        req.user = result.rows[0];
        next();
    } catch (err) {
        return res.status(401).json({ error: 'توکن نامعتبر' });
    }
};

const authorize = (...roles) => {
    return (req, res, next) => {
        if (!req.user) return res.status(401).json({ error: 'احراز هویت نشده' });
        if (!roles.includes(req.user.role)) {
            return res.status(403).json({ error: 'دسترسی غیرمجاز' });
        }
        next();
    };
};

// ------------------- راه‌اندازی اولیه (ساخت مدیر پیش‌فرض) -------------------
const setupInitialAdmin = async () => {
    const adminUsername = process.env.ADMIN_USERNAME || 'admin';
    const adminPassword = process.env.ADMIN_PASSWORD || 'Admin@1234';
    const adminEmail = process.env.ADMIN_EMAIL || 'admin@example.com';

    try {
        const hashed = await bcrypt.hash(adminPassword, 10);
        await pool.query(
            `INSERT INTO users (username, email, password_hash, role, is_verified) 
             VALUES ($1, $2, $3, 'admin', true) 
             ON CONFLICT (username) DO NOTHING`,
            [adminUsername, adminEmail, hashed]
        );
        console.log('✅ مدیر اولیه بررسی/ایجاد شد.');
    } catch (err) {
        console.error('❌ خطا در ساخت مدیر:', err.message);
    }
};

// ------------------- مسیرهای احراز هویت -------------------
// ثبت‌نام
app.post('/api/auth/register', async (req, res) => {
    const { username, email, password, role = 'customer' } = req.body;
    if (!username || !email || !password) {
        return res.status(400).json({ error: 'تمامی فیلدها الزامی است' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query(
            `INSERT INTO users (username, email, password_hash, role) 
             VALUES ($1, $2, $3, $4) RETURNING id, username, email, role`,
            [username, email, hashedPassword, role]
        );
        res.status(201).json({ message: 'ثبت‌نام موفق', user: result.rows[0] });
    } catch (err) {
        if (err.code === '23505') return res.status(400).json({ error: 'نام کاربری یا ایمیل تکراری است' });
        res.status(500).json({ error: 'خطای سرور' });
    }
});

// ورود
app.post('/api/auth/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'اطلاعات نادرست' });

        const user = result.rows[0];
        const match = await bcrypt.compare(password, user.password_hash);
        if (!match) return res.status(401).json({ error: 'اطلاعات نادرست' });

        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '24h' });
        res.cookie('token', token, { httpOnly: true, secure: false, maxAge: 24 * 60 * 60 * 1000 }); // secure: true در HTTPS

        res.json({ message: 'ورود موفق', user: { id: user.id, username: user.username, role: user.role, is_verified: user.is_verified } });
    } catch (err) {
        res.status(500).json({ error: 'خطای سرور' });
    }
});

// خروج
app.post('/api/auth/logout', (req, res) => {
    res.clearCookie('token');
    res.json({ message: 'خارج شدید' });
});

// ------------------- مسیرهای فروشنده (محصولات) -------------------
// ثبت محصول جدید (فقط فروشنده تأییدشده یا مدیر)
app.post('/api/products', authenticate, authorize('seller', 'admin'), async (req, res) => {
    const { name, description, price, stock_quantity } = req.body;
    // اگر فروشنده است، باید تأیید شده باشد
    if (req.user.role === 'seller' && !req.user.is_verified) {
        return res.status(403).json({ error: 'حساب فروشندگی شما تأیید نشده است' });
    }
    const seller_id = req.user.role === 'admin' ? req.body.seller_id || req.user.id : req.user.id;

    try {
        const result = await pool.query(
            `INSERT INTO products (seller_id, name, description, price, stock_quantity) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [seller_id, name, description, price, stock_quantity]
        );
        // لاگ
        await pool.query('INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
            [req.user.id, 'CREATE_PRODUCT', JSON.stringify({ product_id: result.rows[0].id })]);
        res.status(201).json(result.rows[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// دریافت لیست محصولات (همه کاربران)
app.get('/api/products', async (req, res) => {
    try {
        const result = await pool.query('SELECT p.*, u.username as seller_name FROM products p JOIN users u ON p.seller_id = u.id WHERE p.stock_quantity > 0');
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ------------------- مسیر سفارش (با تراکنش) -------------------
app.post('/api/orders', authenticate, authorize('customer'), async (req, res) => {
    const { items } = req.body; // items: [{product_id, quantity}]
    if (!items || items.length === 0) return res.status(400).json({ error: 'سبد خرید خالی است' });

    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        let total = 0;
        const orderItems = [];

        for (const item of items) {
            // قفل کردن ردیف برای جلوگیری از فروش همزمان (SELECT FOR UPDATE)
            const prodResult = await client.query('SELECT * FROM products WHERE id = $1 FOR UPDATE', [item.product_id]);
            if (prodResult.rows.length === 0) throw new Error(`محصول ${item.product_id} یافت نشد`);
            const product = prodResult.rows[0];

            if (product.stock_quantity < item.quantity) throw new Error(`موجودی ${product.name} کافی نیست`);

            // کاهش موجودی
            await client.query('UPDATE products SET stock_quantity = stock_quantity - $1 WHERE id = $2', [item.quantity, item.product_id]);
            total += parseFloat(product.price) * item.quantity;
            orderItems.push({ product_id: item.product_id, quantity: item.quantity, price_at_time: product.price });
        }

        // ثبت سفارش
        const orderResult = await client.query(
            `INSERT INTO orders (customer_id, total_amount) VALUES ($1, $2) RETURNING *`,
            [req.user.id, total]
        );
        const orderId = orderResult.rows[0].id;

        // ثبت آیتم‌های سفارش
        for (const oi of orderItems) {
            await client.query(
                `INSERT INTO order_items (order_id, product_id, quantity, price_at_time) VALUES ($1, $2, $3, $4)`,
                [orderId, oi.product_id, oi.quantity, oi.price_at_time]
            );
        }

        await client.query('COMMIT');
        res.status(201).json({ message: 'سفارش ثبت شد', order_id: orderId, total });
    } catch (err) {
        await client.query('ROLLBACK');
        res.status(400).json({ error: err.message });
    } finally {
        client.release();
    }
});

// ------------------- مسیرهای مدیر -------------------
// تأیید فروشنده
app.put('/api/admin/verify-seller/:userId', authenticate, authorize('admin'), async (req, res) => {
    const { userId } = req.params;
    try {
        await pool.query('UPDATE users SET is_verified = true WHERE id = $1 AND role = $2', [userId, 'seller']);
        await pool.query('INSERT INTO audit_logs (user_id, action, details) VALUES ($1, $2, $3)',
            [req.user.id, 'VERIFY_SELLER', JSON.stringify({ seller_id: userId })]);
        res.json({ message: 'فروشنده تأیید شد' });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// دریافت گزارش (لیست سفارشات به همراه آیتم‌ها)
app.get('/api/admin/reports', authenticate, authorize('admin'), async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT o.id, o.total_amount, o.status, o.created_at, 
                   u.username as customer_name,
                   json_agg(json_build_object('product_name', p.name, 'quantity', oi.quantity, 'price', oi.price_at_time)) as items
            FROM orders o
            JOIN users u ON o.customer_id = u.id
            JOIN order_items oi ON o.id = oi.order_id
            JOIN products p ON oi.product_id = p.id
            GROUP BY o.id, u.username
            ORDER BY o.created_at DESC
        `);
        res.json(result.rows);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// ------------------- راه‌اندازی سرور -------------------
setupInitialAdmin().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 سرور آسان‌خدمت V3 روی پورت ${PORT} اجرا شد`);
    });
});
