require('dotenv').config();

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const sqlite3 = require('sqlite3').verbose();
const crypto = require('crypto');
const fs = require('fs');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'"],
            connectSrc: ["'self'", "ws://localhost:3000", "http://localhost:3000"]
        }
    }
}));

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, 
    max: 100 
});
app.use(limiter);

function validateOrGenerateJWT() {
    if (!process.env.JWT_SECRET || process.env.JWT_SECRET.trim() === '') {
        console.warn('⚠️  Generating new JWT_SECRET...');
        const newSecret = crypto.randomBytes(64).toString('hex');
        process.env.JWT_SECRET = newSecret;
        let envContent = '';
        if (fs.existsSync('.env')) {
            envContent = fs.readFileSync('.env', 'utf8');
        }
        if (envContent.includes('JWT_SECRET=')) {
            envContent = envContent.replace(/JWT_SECRET=.*/, `JWT_SECRET=${newSecret}`);
        } else {
            envContent += `JWT_SECRET=${newSecret}\n`;
        }
        
        fs.writeFileSync('.env', envContent);
        console.log('✅ Generated and saved JWT_SECRET to .env');
        console.log(`🔑 Your JWT_SECRET: ${newSecret.substring(0, 16)}...`);
    } else if (process.env.JWT_SECRET.length < 32) {
        console.error('❌ JWT_SECRET is too short (minimum 32 characters)');
        process.exit(1);
    } else {
        console.log('✅ JWT_SECRET validated successfully');
    }
    
    return process.env.JWT_SECRET;
}

const JWT_SECRET = validateOrGenerateJWT();
const dbPath = process.env.DATABASE_PATH || './messaging.db';
const db = new sqlite3.Database(dbPath, (err) => {
    if (err) {
        console.error('Error opening database:', err);
    } else {
        console.log('Connected to SQLite database');
        initializeDatabase();
    }
});


function initializeDatabase() {
    db.serialize(() => {
        db.run(`CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            public_key TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            sender_id TEXT NOT NULL,
            receiver_id TEXT NOT NULL,
            encrypted_content TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (sender_id) REFERENCES users (id),
            FOREIGN KEY (receiver_id) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS rooms (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            created_by TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES users (id)
        )`);

        db.run(`CREATE TABLE IF NOT EXISTS room_members (
            room_id TEXT NOT NULL,
            user_id TEXT NOT NULL,
            joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (room_id, user_id),
            FOREIGN KEY (room_id) REFERENCES rooms (id),
            FOREIGN KEY (user_id) REFERENCES users (id)
        )`);
    });
}

const verifyToken = (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ error: 'Invalid token' });
    }
};

app.post('/api/register', async (req, res) => {
    try {
        const { username, password, publicKey } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        db.get('SELECT id FROM users WHERE username = ?', [username], async (err, row) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (row) {
                return res.status(400).json({ error: 'Username already exists' });
            }

            const passwordHash = await bcrypt.hash(password, 10);
            const userId = uuidv4();

            db.run('INSERT INTO users (id, username, password_hash, public_key) VALUES (?, ?, ?, ?)', 
                [userId, username, passwordHash, publicKey], function(err) {
                if (err) {
                    return res.status(500).json({ error: 'Failed to create user' });
                }

                const token = jwt.sign({ id: userId, username }, JWT_SECRET, { expiresIn: '24h' });
                res.json({ token, user: { id: userId, username } });
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            if (!user) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password_hash);
            if (!isPasswordValid) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '24h' });
            res.json({ 
                token, 
                user: { 
                    id: user.id, 
                    username: user.username,
                    publicKey: user.public_key
                } 
            });
        });
    } catch (error) {
        res.status(500).json({ error: 'Server error' });
    }
});

app.get('/api/users/:username/publickey', verifyToken, (req, res) => {
    const { username } = req.params;

    db.get('SELECT public_key, username FROM users WHERE username = ?', [username], (err, user) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ publicKey: user.public_key, username: user.username });
    });
});

app.get('/api/users', verifyToken, (req, res) => {
    db.all('SELECT id, username FROM users WHERE id != ?', [req.user.id], (err, users) => {
        if (err) {
            return res.status(500).json({ error: 'Database error' });
        }
        res.json(users);
    });
});

app.get('/api/messages/:userId', verifyToken, (req, res) => {
    const { userId } = req.params;
    const currentUserId = req.user.id;

    db.all(`SELECT m.*, u.username as sender_username 
            FROM messages m 
            JOIN users u ON m.sender_id = u.id 
            WHERE (m.sender_id = ? AND m.receiver_id = ?) 
               OR (m.sender_id = ? AND m.receiver_id = ?)
            ORDER BY m.timestamp ASC`, 
        [currentUserId, userId, userId, currentUserId], 
        (err, messages) => {
            if (err) {
                return res.status(500).json({ error: 'Database error' });
            }
            res.json(messages);
        });
});

const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('authenticate', (token) => {
        try {
            const decoded = jwt.verify(token, JWT_SECRET);
            socket.userId = decoded.id;
            socket.username = decoded.username;
            connectedUsers.set(decoded.id, socket.id);
            
            socket.emit('authenticated', { success: true });
            
            socket.broadcast.emit('user_online', { 
                userId: decoded.id, 
                username: decoded.username 
            });
        } catch (error) {
            socket.emit('authentication_error', { error: 'Invalid token' });
        }
    });

    socket.on('private_message', (data) => {
        const { receiverId, encryptedContent, messageId } = data;
        const senderId = socket.userId;

        if (!senderId) {
            socket.emit('error', { message: 'Not authenticated' });
            return;
        }

        db.run('INSERT INTO messages (id, sender_id, receiver_id, encrypted_content) VALUES (?, ?, ?, ?)',
            [messageId, senderId, receiverId, encryptedContent], function(err) {
            if (err) {
                console.error('Error storing message:', err);
                socket.emit('message_error', { error: 'Failed to store message' });
                return;
            }

            const recipientSocketId = connectedUsers.get(receiverId);
            if (recipientSocketId) {
                io.to(recipientSocketId).emit('new_message', {
                    id: messageId,
                    senderId: senderId,
                    senderUsername: socket.username,
                    encryptedContent: encryptedContent,
                    timestamp: new Date().toISOString()
                });
            }

            socket.emit('message_sent', { messageId });
        });
    });

    socket.on('typing_start', (data) => {
        const recipientSocketId = connectedUsers.get(data.receiverId);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('user_typing', {
                userId: socket.userId,
                username: socket.username
            });
        }
    });

    socket.on('typing_stop', (data) => {
        const recipientSocketId = connectedUsers.get(data.receiverId);
        if (recipientSocketId) {
            io.to(recipientSocketId).emit('user_stopped_typing', {
                userId: socket.userId,
                username: socket.username
            });
        }
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
        if (socket.userId) {
            connectedUsers.delete(socket.userId);
            socket.broadcast.emit('user_offline', { 
                userId: socket.userId, 
                username: socket.username 
            });
        }
    });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});

process.on('SIGINT', () => {
    console.log('Shutting down server...');
    db.close((err) => {
        if (err) {
            console.error(err.message);
        } else {
            console.log('Database connection closed.');
        }
        process.exit(0);
    });
});
