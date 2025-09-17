const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');

// Middleware for authentication
const authMiddleware = (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ message: 'No token provided' });
        }
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        console.error('Authentication error:', error);
        res.status(401).json({ message: 'Invalid token' });
    }
};

// NEW: Register user (sends to pending_users table first)
router.post('/register', async (req, res) => {
    const { username, email, password, phone } = req.body;
    try {
        // Validate required fields
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Username, email, and password are required' });
        }

        // Check if user already exists in users table
        const userExists = await pool.query(
            'SELECT * FROM users WHERE email = $1 OR username = $2', 
            [email, username]
        );
        if (userExists.rows.length > 0) {
            return res.status(400).json({ 
                message: userExists.rows[0].email === email ? 'Email already exists' : 'Username already exists' 
            });
        }

        // Check if user already has a pending request
        const pendingExists = await pool.query(
            'SELECT * FROM pending_users WHERE email = $1 OR username = $2', 
            [email, username]
        );
        if (pendingExists.rows.length > 0) {
            return res.status(400).json({ 
                message: 'Registration request already pending admin approval' 
            });
        }

        // Validate phone number format if provided
        if (phone && !/^\+?\d{10,15}$/.test(phone.replace(/[\s-]/g, ''))) {
            return res.status(400).json({ 
                message: 'Invalid phone number format (must be 10-15 digits, optional + prefix)' 
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert into pending_users table instead of users table
        const result = await pool.query(
            'INSERT INTO pending_users (username, email, password, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [username, email, hashedPassword, phone || null, 'passenger']
        );

        res.status(201).json({ 
            message: 'Registration request submitted. Waiting for admin approval.', 
            pendingUserId: result.rows[0].id 
        });
    } catch (error) {
        console.error('Error creating registration request:', error);
        res.status(500).json({ 
            message: 'Error creating registration request', 
            error: error.message 
        });
    }
});

// Login remains the same (only checks users table, not pending_users)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    try {
        // Modified query to check both email and phone fields
        const result = await pool.query('SELECT * FROM users WHERE email = $1 OR phone = $1', [email]);
        const user = result.rows[0];
        if (!user) {
            return res.status(401).json({ message: 'Invalid email/phone or password' });
        }
        const isValidPassword = await bcrypt.compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid email/phone or password' });
        }
        const token = jwt.sign({ id: user.id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, message: 'Login successful' });
    } catch (error) {
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// Cab request history
router.get('/api/requests', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const result = await pool.query(
            'SELECT * FROM cab_requests WHERE user_id = $1 ORDER BY request_time DESC',
            [userId]
        );
        const requests = result.rows;

        res.status(200).json({
            success: true,
            data: requests
        });
    } catch (error) {
        console.error('Error fetching requests:', error);
        res.status(500).json({
            success: false,
            message: 'Error fetching requests'
        });
    }
});

module.exports = router;

// const express = require('express');
// const router = express.Router();
// const bcrypt = require('bcrypt');
// const jwt = require('jsonwebtoken');
// const pool = require('../config/db');

// // Middleware for authentication
// const authMiddleware = (req, res, next) => {
//     try {
//         const token = req.headers.authorization?.split(' ')[1]; // Expecting "Bearer <token>"
//         if (!token) {
//             return res.status(401).json({ message: 'No token provided' });
//         }
//         const decoded = jwt.verify(token, process.env.JWT_SECRET); // Verify token with secret
//         req.user = decoded; // Attach decoded user info to request
//         next();
//     } catch (error) {
//         console.error('Authentication error:', error);
//         res.status(401).json({ message: 'Invalid token' });
//     }
// };
// router.post('/register', async (req, res) => {
//     const { username, email, password, phone } = req.body;
//     try {
//         // Validate required fields
//         if (!username || !email || !password) {
//             return res.status(400).json({ message: 'Username, email, and password are required' });
//         }

//         // Check if user exists by email or username
//         const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
//         if (userExists.rows.length > 0) {
//             return res.status(400).json({ 
//                 message: userExists.rows[0].email === email ? 'Email already exists' : 'Username already exists' 
//             });
//         }

//         // Validate phone number (optional, but must match format if provided)
//         if (phone && !/^\+?\d{10,15}$/.test(phone.replace(/[\s-]/g, ''))) {
//             return res.status(400).json({ message: 'Invalid phone number format (must be 10-15 digits, optional + prefix)' });
//         }

//         // Hash password
//         const hashedPassword = await bcrypt.hash(password, 10);

//         // Insert user into database
//         const result = await pool.query(
//             'INSERT INTO users (username, email, password, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
//             [username, email, hashedPassword, phone || null, 'passenger']
//         );

//         res.status(201).json({ 
//             message: 'User registered successfully', 
//             userId: result.rows[0].id 
//         });
//     } catch (error) {
//         console.error('Error registering user:', error);
//         res.status(500).json({ 
//             message: 'Error registering user', 
//             error: error.message 
//         });
//     }
// });


// router.post('/login', async (req, res) => {
//     const { email, password } = req.body;
//     try {
//         // Modified query to check both email and phone fields
//         const result = await pool.query('SELECT * FROM users WHERE email = $1 OR phone = $1', [email]);
//         const user = result.rows[0];
//         if (!user) {
//             return res.status(401).json({ message: 'Invalid email/phone or password' });
//         }
//         const isValidPassword = await bcrypt.compare(password, user.password);
//         if (!isValidPassword) {
//             return res.status(401).json({ message: 'Invalid email/phone or password' });
//         }
//         const token = jwt.sign({ id: user.id, role: 'user' }, process.env.JWT_SECRET, { expiresIn: '1h' });
//         res.json({ token, message: 'Login successful' });
//     } catch (error) {
//         res.status(500).json({ message: 'Error logging in', error: error.message });
//     }
// });




// // Cab request history
// router.get('/api/requests', authMiddleware, async (req, res) => {
//     try {
//         const userId = req.user.id; // Extract user ID from authenticated token

//         // Fetch cab requests for the authenticated user from PostgreSQL
//         const result = await pool.query(
//             'SELECT * FROM cab_requests WHERE user_id = $1 ORDER BY request_time DESC',
//             [userId]
//         );
//         const requests = result.rows;

//         res.status(200).json({
//             success: true,
//             data: requests
//         });
//     } catch (error) {
//         console.error('Error fetching requests:', error);
//         res.status(500).json({
//             success: false,
//             message: 'Error fetching requests'
//         });
//     }
// });


// module.exports = router;




