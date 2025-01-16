import express, { Request, Response, NextFunction } from 'express';
import { PrismaClient } from '@prisma/client';
import fs from 'fs';
import path from 'path';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import multer from 'multer';
import dotenv from 'dotenv';
import cookieParser from 'cookie-parser';

const authMiddleware = require('./middleware/auth');
import logger from './middleware/logger'; // Adjust the path if needed

dotenv.config();

const app = express();

app.use(logger);

app.use(cookieParser());

app.use(express.static(path.join(__dirname, 'public')));

app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const prisma = new PrismaClient();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';

app.use(express.json());

const upload = multer({
    storage: multer.diskStorage({
        destination: (req, file, cb) => {
            // Specify the directory where to store the uploaded files
            const uploadPath = path.join(__dirname, 'uploads');  // 'uploads' folder in the project root
            fs.mkdirSync(uploadPath, { recursive: true });  // Ensure the folder exists
            cb(null, uploadPath);
        },
        filename: (req, file, cb) => {
            const fileExtension = path.extname(file.originalname);  // Get the file extension
            const filename = `${Date.now()}${fileExtension}`;  // Create a unique filename using timestamp
            cb(null, filename);
        }
    })
});


app.get('/login', (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/admin', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/products', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-products.html'));
});

app.get('/admin/product/new', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'product-form.html'));
});

app.get('/admin/product/edit/:id', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'product-edit.html'));
});

app.get('/admin/orders', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'admin-orders.html'));
});

app.get('/admin/order/:id', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'order-detail.html'));
});

app.get('/admin/administrators', authMiddleware, (req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', 'user-form.html'));
});



app.post('/api/auth/login', async (req: Request, res: Response) => {
    const { username, password } = req.body;

    try {
        const user = await prisma.user.findUnique({
            where: { username },
        });

        if (!user) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }

        const passwordMatch = await bcrypt.compare(password, user.password);
        if (!passwordMatch) {
            res.status(401).json({ error: 'Invalid credentials' });
            return;
        }


        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            JWT_SECRET,
            { expiresIn: '1h' }
        );

        // Set the token in an HTTP-only cookie
        res.cookie('token', token, {
            httpOnly: true, // Ensures the cookie is not accessible via JavaScript (important for XSS protection)
            secure: process.env.NODE_ENV === 'production', // Only use 'secure' cookies in production (over HTTPS)
            maxAge: 3600000, // 1 hour expiration
            sameSite: 'strict', // Prevent cross-site request forgery (CSRF)
        });

        res.json({ message: 'Login successful' });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'An error occurred during login' });
    }
});

app.post('/api/auth/logout', (req: Request, res: Response) => {
    res.clearCookie('token', {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'strict',
    });
    res.status(200).json({ message: 'Logged out successfully' });
});

app.get('/api/auth/users', authMiddleware, async (req: Request, res: Response) => {
    try {
        const adminUsers = await prisma.user.findMany({
            select: { id: true, username: true }
        });

        res.status(200).json(adminUsers);
    } catch (error) {
        console.error('Failed to fetch admin users:', error);
        res.status(500).json({ error: 'Failed to fetch admin users' });
    }
});

app.post('/api/auth/user', authMiddleware, async (req: Request, res: Response) => {
    try {
        const { username, password } = req.body;
        const hashedPassword = await bcrypt.hash(password, 10);
        const user = await prisma.user.create({
            data: { username, password: hashedPassword },
        });

        res.json(user);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create user' });
    }
});

app.delete('/api/auth/user/:id', authMiddleware, async (req: Request, res: Response) => {
    try {
        const { id } = req.params;
        await prisma.user.delete({ where: { id: parseInt(id, 10) } });
        res.status(204).send();
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to delete user' });
    }
});

app.post('/api/product', upload.single('image'), authMiddleware, async (req: Request, res: Response) => {
    try {
        if (!req.file) {
            res.status(400).json({ error: 'Image file is required' });
            return;
        }

        const { name, description, price } = req.body;
        const imageUrl = `/uploads/${req.file.filename}`;

        const product = await prisma.product.create({
            data: {
                name,
                description,
                price: parseFloat(price),
                imageUrl,
            },
        });

        res.json(product);
    } catch (error) {
        console.error('Error saving product:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

app.get('/api/product', async (req: Request, res: Response) => {
    try {
        const products = await prisma.product.findMany();
        res.json(products);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch products' });
    }
});

app.get('/api/product/:id', authMiddleware, async (req: Request, res: Response) => {
    try {
        const product = await prisma.product.findUnique({
            where: { id: parseInt(req.params.id, 10) },
        });

        if (!product) {
            res.status(404).json({ error: 'Product not found' });
        }

        res.json(product);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch product' });
    }
});

app.post('/api/product', upload.single('image'), authMiddleware, async (req: Request, res: Response) => {
    try {
        if (!req.file) {
            res.status(400).json({ error: 'Image file is required' });
            return;
        }

        const { name, description, price } = req.body;

        const imageUrl = `/uploads/${req.file.filename}`;

        const product = await prisma.product.create({
            data: {
                name,
                description,
                price: parseFloat(price),
                imageUrl
            }
        });

        res.json(product);
    } catch (error) {
        console.error('Error saving product:', error);
        res.status(500).json({ error: 'Failed to create product' });
    }
});

app.put('/api/product/:id', upload.single('image'), async (req, res) => {
    const { id } = req.params;
    const { name, description, price } = req.body;

    try {
        const product = await prisma.product.update({
            where: { id: parseInt(id, 10) },
            data: {
                name,
                description,
                price: parseFloat(price),
                ...(req.file && { imageUrl: `/uploads/${req.file.filename}` }),
            },
        });
        res.json(product);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to update product' });
    }
});



app.get('/api/order', authMiddleware, async (req: Request, res: Response) => {
    try {
        const orders = await prisma.order.findMany({
            include: { items: { include: { product: true } } },
        });
        res.json(orders);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch orders' });
    }
});

app.get('/api/order/:id', authMiddleware, async(req: Request, res: Response) => {
    try {
        const order = await prisma.order.findUnique({
            where: { id: parseInt(req.params.id, 10) },
            include: { items: { include: { product: true } } },
        });

        if (!order) {
            res.status(404).json({ error: 'Order not found' });
        }

        res.json(order);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to fetch order' });
    }
});

app.post('/api/order', async (req: Request, res: Response) => {
    try {
        const { name, email, items, total } = req.body;

        const order = await prisma.order.create({
            data: {
                name,
                email,
                total,
                items: {
                    create: items.map((item: any) => ({
                        quantity: item.quantity,
                        price: item.price,
                        product: { connect: { id: item.productId } },
                    })),
                },
            },
        });

        res.json(order);
    } catch (error) {
        console.error(error);
        res.status(500).json({ error: 'Failed to create order' });
    }
});



app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.use((req: Request, res: Response) => {
    res.sendFile(path.join(__dirname, 'public', '404.html'));
});


app.listen(PORT, () => {
    console.log('Server running on port http://localhost:' + process.env.PORT);
});

export default app;