const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 5000;

// Directories
const DATA_DIR = path.join(__dirname, 'data');
const IMAGES_DIR = path.join(__dirname, 'images');

// Ensure images directory exists
if (!fs.existsSync(IMAGES_DIR)) {
    fs.mkdirSync(IMAGES_DIR, { recursive: true });
}

// Middleware
app.use(cors());
app.use(express.json({ limit: '5mb' })); // Increase limit for base64 images

// Serve static images
app.use('/images', express.static(IMAGES_DIR));

// Helper functions for JSON file operations
const readData = (filename) => {
    const filepath = path.join(DATA_DIR, filename);
    if (!fs.existsSync(filepath)) {
        return [];
    }
    const data = fs.readFileSync(filepath, 'utf8');
    return JSON.parse(data);
};

const writeData = (filename, data) => {
    const filepath = path.join(DATA_DIR, filename);
    fs.writeFileSync(filepath, JSON.stringify(data, null, 2));
};

// ============ AUTH ROUTES ============
app.post('/api/auth/register', (req, res) => {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'All fields are required' });
    }

    const users = readData('users.json');

    // Check if email exists
    if (users.find(u => u.email === email)) {
        return res.status(400).json({ error: 'Email already registered' });
    }

    const newUser = {
        id: uuidv4(),
        name,
        email,
        password, // In real app, hash this!
        initials: name.split(' ').map(n => n[0]).join('').toUpperCase().slice(0, 2),
        avatarColor: ['#3b82f6', '#10b981', '#f59e0b', '#ec4899', '#8b5cf6'][Math.floor(Math.random() * 5)],
        role: 'Member',
        bio: '',
        createdAt: new Date().toISOString()
    };

    users.push(newUser);
    writeData('users.json', users);

    // Don't return password
    const { password: _, ...userWithoutPassword } = newUser;
    res.status(201).json(userWithoutPassword);
});

app.post('/api/auth/login', (req, res) => {
    const { email, password } = req.body;

    const users = readData('users.json');
    const user = users.find(u => u.email === email && u.password === password);

    if (!user) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

// ============ USER ROUTES ============
app.get('/api/users/:id', (req, res) => {
    const users = readData('users.json');
    const user = users.find(u => u.id === req.params.id);

    if (!user) {
        return res.status(404).json({ error: 'User not found' });
    }

    const { password: _, ...userWithoutPassword } = user;
    res.json(userWithoutPassword);
});

app.put('/api/users/:id', (req, res) => {
    const users = readData('users.json');
    const index = users.findIndex(u => u.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }

    const updatedUser = { ...users[index], ...req.body };
    users[index] = updatedUser;
    writeData('users.json', users);

    const { password: _, ...userWithoutPassword } = updatedUser;
    res.json(userWithoutPassword);
});

app.get('/api/users', (req, res) => {
    const users = readData('users.json');
    const usersWithoutPasswords = users.map(({ password, ...user }) => user);
    res.json(usersWithoutPasswords);
});

app.delete('/api/users/:id', (req, res) => {
    const users = readData('users.json');
    const filtered = users.filter(u => u.id !== req.params.id);

    if (filtered.length === users.length) {
        return res.status(404).json({ error: 'User not found' });
    }

    writeData('users.json', filtered);
    res.json({ success: true });
});

// Upload avatar image
app.post('/api/users/:id/avatar', (req, res) => {
    const { imageData } = req.body; // base64 image

    if (!imageData) {
        return res.status(400).json({ error: 'No image data provided' });
    }

    const users = readData('users.json');
    const index = users.findIndex(u => u.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Extract base64 data and extension
    const matches = imageData.match(/^data:image\/(\w+);base64,(.+)$/);
    if (!matches) {
        return res.status(400).json({ error: 'Invalid image format' });
    }

    const extension = matches[1];
    const base64Data = matches[2];
    const filename = `avatar_${req.params.id}_${Date.now()}.${extension}`;
    const filepath = path.join(IMAGES_DIR, filename);

    // Delete old avatar if exists
    if (users[index].avatarImage) {
        const oldFilename = users[index].avatarImage.split('/').pop();
        const oldPath = path.join(IMAGES_DIR, oldFilename);
        if (fs.existsSync(oldPath)) {
            fs.unlinkSync(oldPath);
        }
    }

    // Save new image
    fs.writeFileSync(filepath, base64Data, 'base64');

    // Update user with relative image path (frontend will prepend API base)
    const avatarImage = `/images/${filename}`;
    users[index].avatarImage = avatarImage;
    writeData('users.json', users);

    const { password: _, ...userWithoutPassword } = users[index];
    res.json(userWithoutPassword);
});

// Delete avatar image
app.delete('/api/users/:id/avatar', (req, res) => {
    const users = readData('users.json');
    const index = users.findIndex(u => u.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'User not found' });
    }

    // Delete old avatar file if exists
    if (users[index].avatarImage) {
        const filename = users[index].avatarImage.split('/').pop();
        const filepath = path.join(IMAGES_DIR, filename);
        if (fs.existsSync(filepath)) {
            fs.unlinkSync(filepath);
        }
    }

    users[index].avatarImage = null;
    writeData('users.json', users);

    const { password: _, ...userWithoutPassword } = users[index];
    res.json(userWithoutPassword);
});

// ============ SPACES ROUTES ============
app.get('/api/spaces', (req, res) => {
    const spaces = readData('spaces.json');
    res.json(spaces);
});

app.post('/api/spaces', (req, res) => {
    const spaces = readData('spaces.json');
    const newSpace = {
        id: uuidv4(),
        ...req.body,
        createdAt: new Date().toISOString(),
        userCount: 0,
        memberCount: 1,
        isOnline: false
    };
    spaces.push(newSpace);
    writeData('spaces.json', spaces);
    res.status(201).json(newSpace);
});

app.get('/api/spaces/:id', (req, res) => {
    const spaces = readData('spaces.json');
    const space = spaces.find(s => s.id === req.params.id);

    if (!space) {
        return res.status(404).json({ error: 'Space not found' });
    }
    res.json(space);
});

app.put('/api/spaces/:id', (req, res) => {
    const spaces = readData('spaces.json');
    const index = spaces.findIndex(s => s.id === req.params.id);

    if (index === -1) {
        return res.status(404).json({ error: 'Space not found' });
    }

    spaces[index] = { ...spaces[index], ...req.body };
    writeData('spaces.json', spaces);
    res.json(spaces[index]);
});

app.delete('/api/spaces/:id', (req, res) => {
    const spaces = readData('spaces.json');
    const filtered = spaces.filter(s => s.id !== req.params.id);
    writeData('spaces.json', filtered);
    res.json({ success: true });
});

// ============ NOTIFICATIONS ROUTES ============
app.get('/api/notifications', (req, res) => {
    const { userId } = req.query;
    const notifications = readData('notifications.json');
    const userNotifications = userId
        ? notifications.filter(n => n.userId === userId)
        : notifications;
    res.json(userNotifications);
});

app.post('/api/notifications', (req, res) => {
    const notifications = readData('notifications.json');
    const newNotification = {
        id: uuidv4(),
        ...req.body,
        read: false,
        time: 'Just now',
        createdAt: new Date().toISOString()
    };
    notifications.unshift(newNotification);
    writeData('notifications.json', notifications);
    res.status(201).json(newNotification);
});

app.put('/api/notifications/:id/read', (req, res) => {
    const notifications = readData('notifications.json');
    const index = notifications.findIndex(n => n.id === req.params.id);

    if (index !== -1) {
        notifications[index].read = true;
        writeData('notifications.json', notifications);
    }
    res.json({ success: true });
});

app.put('/api/notifications/read-all', (req, res) => {
    const notifications = readData('notifications.json');
    notifications.forEach(n => n.read = true);
    writeData('notifications.json', notifications);
    res.json({ success: true });
});

// ============ FRIENDS ROUTES ============
app.get('/api/friends', (req, res) => {
    const { userId } = req.query;
    const friends = readData('friends.json');
    const userFriends = userId
        ? friends.filter(f => f.userId === userId || f.friendId === userId)
        : friends;
    res.json(userFriends);
});

app.post('/api/friends', (req, res) => {
    const friends = readData('friends.json');
    const newFriend = {
        id: uuidv4(),
        ...req.body,
        status: 'pending',
        createdAt: new Date().toISOString()
    };
    friends.push(newFriend);
    writeData('friends.json', friends);
    res.status(201).json(newFriend);
});

app.put('/api/friends/:id/accept', (req, res) => {
    const friends = readData('friends.json');
    const index = friends.findIndex(f => f.id === req.params.id);

    if (index !== -1) {
        friends[index].status = 'accepted';
        writeData('friends.json', friends);
    }
    res.json({ success: true });
});

app.delete('/api/friends/:id', (req, res) => {
    const friends = readData('friends.json');
    const filtered = friends.filter(f => f.id !== req.params.id);
    writeData('friends.json', filtered);
    res.json({ success: true });
});

// ============ MESSAGES ROUTES ============
app.get('/api/messages/:spaceId', (req, res) => {
    const messages = readData('messages.json');
    const spaceMessages = messages.filter(m => m.spaceId === req.params.spaceId);
    res.json(spaceMessages);
});

app.post('/api/messages/:spaceId', (req, res) => {
    const messages = readData('messages.json');
    const newMessage = {
        id: uuidv4(),
        spaceId: req.params.spaceId,
        ...req.body,
        time: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
        createdAt: new Date().toISOString()
    };
    messages.push(newMessage);
    writeData('messages.json', messages);
    res.status(201).json(newMessage);
});

// ============ FILES/UPLOADS ROUTES ============
app.get('/api/files/:spaceId', (req, res) => {
    const files = readData('files.json');
    const spaceFiles = files.filter(f => f.spaceId === req.params.spaceId);
    res.json(spaceFiles);
});

app.post('/api/files/:spaceId', (req, res) => {
    const files = readData('files.json');
    const newFile = {
        id: uuidv4(),
        spaceId: req.params.spaceId,
        ...req.body,
        time: 'Just now',
        createdAt: new Date().toISOString()
    };
    files.push(newFile);
    writeData('files.json', files);
    res.status(201).json(newFile);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 CollabSpace API running on http://localhost:${PORT}`);

    // Ensure data directory exists
    if (!fs.existsSync(DATA_DIR)) {
        fs.mkdirSync(DATA_DIR, { recursive: true });
    }
});
