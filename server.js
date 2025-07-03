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

// JWT Secret - Use environment variable
const JWT_SECRET = process.env.JWT_SECRET || '01b266af359ffb49db8fe9f15330f083ad831b5de531555f929d6e4ad8342e3e2fdd72a5fbefd8b5d09eabdb049327b579066d153fddc1edb0419b78b014b098';

// Socket.io connection handling
const connectedUsers = new Map();

io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Join room with user ID
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
                connectedUsers.set(socket.userId, {
                    socketId: socket.id,
                    username: user.username,
                    status: 'online'
                });

                // Broadcast user online status
                socket.broadcast.emit('userOnline', {
                    userId: user._id,
                    username: user.username
                });

                // Send online users list
                socket.emit('onlineUsers', Array.from(connectedUsers.values()));

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

    // Handle new messages
    socket.on('sendMessage', async (messageData) => {
        try {
            const { content, recipientId } = messageData;

            if (!socket.userId) {
                socket.emit('error', 'Not authenticated');
                return;
            }

            // Create message in database
            const message = new Message({
                sender: socket.userId,
                recipient: recipientId,
                content: content,
                timestamp: new Date()
            });

            await message.save();

            // Populate sender info
            await message.populate('sender', 'username');

            // Send to recipient if online
            const recipientUser = connectedUsers.get(recipientId);
            if (recipientUser) {
                io.to(recipientUser.socketId).emit('newMessage', {
                    _id: message._id,
                    sender: message.sender,
                    content: message.content,
                    timestamp: message.timestamp,
                    isNew: true
                });
            }

            // Confirm to sender
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

    // Handle typing indicators
    socket.on('typing', (data) => {
        if (!socket.userId) {
            return;
        }

        const recipientUser = connectedUsers.get(data.recipientId);
        if (recipientUser) {
            io.to(recipientUser.socketId).emit('userTyping', {
                userId: socket.userId,
                username: socket.username,
                isTyping: data.isTyping
            });
        }
    });

    // Handle disconnection
    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);

        if (socket.userId) {
            connectedUsers.delete(socket.userId);

            // Broadcast user offline status
            socket.broadcast.emit('userOffline', {
                userId: socket.userId,
                username: socket.username
            });
        }
    });
});

// Authentication Routes
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

        // Validate input
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        // Check if user exists
        const existingUser = await User.findOne({
            $or: [{ email }, { username }]
        });

        if (existingUser) {
            return res.status(400).json({ error: 'User already exists' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create user
        const user = new User({
            username,
            email,
            password: hashedPassword
        });

        await user.save();

        // Generate JWT
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Registration failed' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        // Validate input
        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Find user
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }

        // Generate JWT
        const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '7d' });

        res.json({
            token,
            user: {
                id: user._id,
                username: user.username,
                email: user.email
            }
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
        if (!token) {
            return res.status(401).json({ error: 'No token provided' });
        }

        const decoded = jwt.verify(token, JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.error('Token verification error:', error);
        return res.status(401).json({ error: 'Invalid token' });
    }
};

// Get users for chat
app.get('/api/users', verifyToken, async (req, res) => {
    try {
        const users = await User.find({ _id: { $ne: req.userId } })
            .select('username email');

        res.json(users);
    } catch (error) {
        console.error('Fetch users error:', error);
        res.status(500).json({ error: 'Failed to fetch users' });
    }
});

// Get messages between users
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

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});