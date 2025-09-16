const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
// CHANGE: Import the provided authenticate middleware
const { authenticate } = require('../middleware/auth'); // Adjust path based on your project structure

router.post('/register', async (req, res) => {
    const { username, email, password, phone } = req.body;
    try {
        // Validate required fields
        if (!username || !email || !password) {
            return res.status(400).json({ message: 'Username, email, and password are required' });
        }

        // CHANGE: Check for existing user in both 'users' and 'pending_users' tables to prevent duplicates.
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        const pendingExists = await pool.query('SELECT * FROM pending_users WHERE email = $1 OR username = $2', [email, username]);
        if (userExists.rows.length > 0 || pendingExists.rows.length > 0) {
            let message = 'Username or email already in use';
            if (userExists.rows.length > 0) {
                message = userExists.rows[0].email === email ? 'Email already registered' : 'Username already registered';
            } else if (pendingExists.rows.length > 0) {
                message = pendingExists.rows[0].email === email ? 'Email registration pending approval' : 'Username registration pending approval';
            }
            return res.status(400).json({ message });
        }

        // Validate phone number (optional, but must match format if provided)
        if (phone && !/^\+?\d{10,15}$/.test(phone.replace(/[\s-]/g, ''))) {
            return res.status(400).json({ message: 'Invalid phone number format (must be 10-15 digits, optional + prefix)' });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // CHANGE: Insert into 'pending_users' instead of 'users' to await admin approval.
        const result = await pool.query(
            'INSERT INTO pending_users (username, email, password, phone, role) VALUES ($1, $2, $3, $4, $5) RETURNING id',
            [username, email, hashedPassword, phone || null, 'passenger']
        );

        // CHANGE: Updated response message to indicate pending status.
        res.status(201).json({ 
            message: 'Registration submitted for admin approval', 
            pendingId: result.rows[0].id 
        });
    } catch (error) {
        console.error('Error registering user:', error);
        res.status(500).json({ 
            message: 'Error registering user', 
            error: error.message 
        });
    }
});

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
        // CHANGE: Use actual user role from database in JWT payload for consistency with middleware.
        const token = jwt.sign({ id: user.id, role: user.role }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token, message: 'Login successful' });
    } catch (error) {
        console.error('Error logging in:', error);
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// NEW: Route to list all pending registrations, accessible only to admins.
// Uses authenticate middleware with 'admin' role.
router.get('/pending-registrations', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query('SELECT id, username, email, phone, created_at FROM pending_users ORDER BY created_at DESC');
        res.json(result.rows);
    } catch (error) {
        console.error('Error fetching pending registrations:', error);
        res.status(500).json({ message: 'Error fetching pending registrations' });
    }
});

// NEW: Route for admins to approve a pending registration.
// Moves data from 'pending_users' to 'users' and deletes from pending.
router.post('/approve-registration/:pendingId', authenticate('admin'), async (req, res) => {
    try {
        const pendingResult = await pool.query('SELECT * FROM pending_users WHERE id = $1', [req.params.pendingId]);
        if (pendingResult.rows.length === 0) {
            return res.status(404).json({ message: 'Pending registration not found' });
        }
        const pendingUser = pendingResult.rows[0];

        // Insert into users
        await pool.query(
            'INSERT INTO users (username, email, password, phone, role) VALUES ($1, $2, $3, $4, $5)',
            [pendingUser.username, pendingUser.email, pendingUser.password, pendingUser.phone, pendingUser.role]
        );

        // Delete from pending
        await pool.query('DELETE FROM pending_users WHERE id = $1', [req.params.pendingId]);

        res.json({ message: 'Registration approved successfully' });
    } catch (error) {
        console.error('Error approving registration:', error);
        res.status(500).json({ message: 'Error approving registration' });
    }
});

// NEW: Route for admins to reject a pending registration.
// Deletes from 'pending_users'.
router.post('/reject-registration/:pendingId', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query('DELETE FROM pending_users WHERE id = $1 RETURNING id', [req.params.pendingId]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Pending registration not found' });
        }
        res.json({ message: 'Registration rejected successfully' });
    } catch (error) {
        console.error('Error rejecting registration:', error);
        res.status(500).json({ message: 'Error rejecting registration' });
    }
});

// Cab request history
// No changes; remains unaffected as it operates on authenticated users from 'users' table.
router.get('/api/requests', authenticate('passenger'), async (req, res) => {
    try {
        const userId = req.user.id; // Extract user ID from authenticated token

        // Fetch cab requests for the authenticated user from PostgreSQL
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


