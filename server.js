const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Message = require('./models/Message');
const User = require('./models/User');

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "http://localhost:3000",
        methods: ["GET", "POST"]
    }
});

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/chatapp', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || '01b266af359ffb49db8fe9f15330f083ad831b5de531555f929d6e4ad8342e3e2fdd72a5fbefd8b5d09eabdb049327b579066d153fddc1edb0419b78b014b098';

// Socket.io connection handling
const connectedUsers = new Map(); // userId -> [{socketId, username, status}]

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    socket.on('join', async (userData) => {
        try {
            const token = userData.token;
            if (!token) {
                console.log('No token provided');
                socket.emit('authError', 'No token provided');
                return;
            }

            const decoded = jwt.verify(token, JWT_SECRET);
            const user = await User.findById(decoded.userId);

            if (user) {
                socket.userId = user._id.toString();
                socket.username = user.username;

                const userSockets = connectedUsers.get(socket.userId) || [];
                if (userSockets.length === 0) {
                    socket.broadcast.emit('userOnline', {
                        userId: user._id,
                        username: user.username
                    });
                }
                userSockets.push({
                    socketId: socket.id,
                    username: user.username,
                    status: 'online'
                });
                connectedUsers.set(socket.userId, userSockets);

                const onlineUsersList = Array.from(connectedUsers.keys()).map(userId => ({
                    userId,
                    username: connectedUsers.get(userId)[0].username
                }));
                socket.emit('onlineUsers', onlineUsersList);

                console.log(`User ${user.username} joined successfully`);
            } else {
                console.log('User not found');
                socket.emit('authError', 'User not found');
            }
        } catch (error) {
            console.error('Join error:', error.message);
            if (error.name === 'JsonWebTokenError') {
                socket.emit('authError', 'Invalid token');
            } else if (error.name === 'TokenExpiredError') {
                socket.emit('authError', 'Token expired');
            } else {
                socket.emit('authError', 'Authentication failed');
            }
        }
    });

    socket.on('sendMessage', async (messageData) => {
        try {
            const { content, recipientId } = messageData;

            if (!socket.userId) {
                socket.emit('error', 'Not authenticated');
                return;
            }

            const message = new Message({
                sender: socket.userId,
                recipient: recipientId,
                content: content,
                timestamp: new Date()
            });

            await message.save();
            await message.populate('sender', 'username');

            const recipientSockets = connectedUsers.get(recipientId) || [];
            recipientSockets.forEach(socketObj => {
                io.to(socketObj.socketId).emit('newMessage', {
                    _id: message._id,
                    sender: message.sender,
                    content: message.content,
                    timestamp: message.timestamp,
                    isNew: true
                });
            });

            socket.emit('messageSent', {
                _id: message._id,
                sender: message.sender,
                recipient: recipientId,
                content: message.content,
                timestamp: message.timestamp
            });
        } catch (error) {
            console.error('Send message error:', error);
            socket.emit('error', 'Failed to send message');
        }
    });

    socket.on('typing', (data) => {
        if (!socket.userId) return;

        const recipientSockets = connectedUsers.get(data.recipientId) || [];
        recipientSockets.forEach(socketObj => {
            io.to(socketObj.socketId).emit('userTyping', {
                userId: socket.userId,
                username: socket.username,
                isTyping: data.isTyping
            });
        });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);

        if (socket.userId) {
            const userSockets = connectedUsers.get(socket.userId) || [];
            const updatedSockets = userSockets.filter(s => s.socketId !== socket.id);
            if (updatedSockets.length === 0) {
                connectedUsers.delete(socket.userId);
                socket.broadcast.emit('userOffline', {
                    userId: socket.userId,
                    username: socket.username
                });
            } else {
                connectedUsers.set(socket.userId, updatedSockets);
            }
        }
    });
});

// Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        const existingUser = await User.findOne({ $or: [{ email }, { username }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const user = new User({ username, email, password: hashedPassword });
        await user.save();

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({
            token,
            user: { id: user._id, username: user.username, email: user.email }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        const user = await User.findOne({ username });
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({
            token,
            user: { id: user._id, username: user.username, email: user.email }
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Login failed' });
    }
});

// Middleware to verify JWT
const verifyToken = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'No token provided' });

        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        res.status(401).json({ error: 'Invalid token' });
    }
};

// API Routes
app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.userId } }).select('username email');
        const usersWithUnread = await Promise.all(users.map(async (user) => {
            const unreadCount = await Message.countDocuments({
                sender: user._id,
                recipient: req.userId,
                isRead: false
            });
            return { ...user.toObject(), hasUnread: unreadCount > 0 };
        }));
        res.json(usersWithUnread);
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

app.get('/api/messages/:userId', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params;
        const messages = await Message.find({
            $or: [
                { sender: req.userId, recipient: userId },
                { sender: userId, recipient: req.userId }
            ]
        })
            .populate('sender', 'username')
            .sort({ timestamp: 1 });
        res.json(messages);
    } catch (error) {
        console.error('Fetch messages error:', error);
        res.status(500).json({ error: 'Failed to fetch messages' });
    }
});

app.post('/api/messages/:userId/read', verifyToken, async (req, res) => {
    try {
        const { userId } = req.params;
        await Message.updateMany(
            { sender: userId, recipient: req.userId, isRead: false },
            { $set: { isRead: true } }
        );
        res.json({ success: true });
    } catch (error) {
        console.error('Mark messages as read error:', error);
        res.status(500).json({ error: 'Failed to mark messages as read' });
    }
});

app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});