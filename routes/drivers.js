const express = require('express');
const router = express.Router();
const pool = require('../config/db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

router.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    next();
});

// Helper function to verify token
const verifyToken = (req, res, next) => {
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) {
        return res.status(401).json({ success: false, message: 'No token provided' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.driverId = decoded.id;
        req.vehicleType = decoded.vehicle_type;
        next();
    } catch (error) {
        return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
};

// DRIVER REGISTRATION ENDPOINT
router.post('/register', async (req, res) => {
    try {
        const { name, email, phone, vehicle_type, vehicle_number, password } = req.body;

        // Validate required fields
        const requiredFields = { name, email, phone, vehicle_type, vehicle_number, password };
        const missingFields = Object.entries(requiredFields)
            .filter(([_, value]) => !value)
            .map(([field]) => field);

        if (missingFields.length > 0) {
            return res.status(400).json({ 
                success: false,
                message: `Missing required fields: ${missingFields.join(', ')}`
            });
        }

        // Check if email already exists
        const existingDriver = await pool.query(
            'SELECT id FROM drivers WHERE email = $1', 
            [email]
        );

        if (existingDriver.rows.length > 0) {
            return res.status(409).json({
                success: false,
                message: 'Email already registered'
            });
        }

        // Hash password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create new driver
        const newDriver = await pool.query(
            `INSERT INTO drivers 
             (name, email, phone, vehicle_type, vehicle_number, password)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING id, name, email, phone, vehicle_type, vehicle_number`,
            [name, email, phone, vehicle_type, vehicle_number, hashedPassword]
        );

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: newDriver.rows[0].id, 
                role: 'driver', 
                vehicle_type: newDriver.rows[0].vehicle_type 
            },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.status(201).json({
            success: true,
            message: 'Registration successful',
            token,
            driver: newDriver.rows[0]
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// DRIVER LOGIN ENDPOINT
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Find driver by email
        const result = await pool.query(
            'SELECT * FROM drivers WHERE email = $1',
            [email]
        );

        if (result.rows.length === 0) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        const driver = result.rows[0];
        
        // Compare passwords
        const isMatch = await bcrypt.compare(password, driver.password);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

        // Generate JWT token
        const token = jwt.sign(
            { 
                id: driver.id, 
                role: 'driver', 
                vehicle_type: driver.vehicle_type 
            },
            process.env.JWT_SECRET,
            { expiresIn: '8h' }
        );

        res.json({
            success: true,
            token,
            driver: {
                id: driver.id,
                name: driver.name,
                email: driver.email,
                phone: driver.phone,
                vehicle_type: driver.vehicle_type,
                vehicle_number: driver.vehicle_number
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// DRIVER PROFILE ENDPOINT
router.get('/profile', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, phone, vehicle_type, vehicle_number FROM drivers WHERE id = $1',
            [req.driverId]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ success: false, message: 'Driver not found' });
        }

        res.json({
            success: true,
            driver: result.rows[0]
        });

    } catch (error) {
        console.error('Profile error:', error);
        res.status(500).json({
            success: false,
            message: 'Internal server error',
            error: error.message
        });
    }
});

// ASSIGNED REQUESTS ENDPOINT
router.get('/assigned-requests', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                cr.id, 
                cr.pickup_location, 
                cr.dropoff_location, 
                cr.status, 
                cr.created_at,
                cr.request_time,
                cr.fare_amount,
                u.username AS customer_name,
                u.phone AS customer_phone,
                u.email AS customer_email
             FROM cab_requests cr
             JOIN users u ON cr.user_id = u.id
             WHERE cr.driver_id = $1
             ORDER BY 
                CASE cr.status
                    WHEN 'in_progress' THEN 1
                    WHEN 'accepted' THEN 2
                    WHEN 'completed' THEN 3
                    ELSE 4
                END,
                cr.created_at DESC`,
            [req.driverId]
        );

        // Format the data for better frontend display
        const requests = result.rows.map(request => ({
            ...request,
            formatted_date: new Date(request.request_time || request.created_at).toLocaleString(),
            status_display: request.status.replace('_', ' ').toUpperCase()
        }));

        res.json({
            success: true,
            requests: requests
        });

    } catch (error) {
        console.error('Assigned requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch assigned requests',
            error: error.message
        });
    }
});

// COMPLETE REQUEST ENDPOINT
router.post('/complete-request', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.body;

        // Verify the request exists and belongs to this driver
        const requestCheck = await pool.query(
            `SELECT id, status FROM cab_requests 
             WHERE id = $1 AND driver_id = $2`,
            [requestId, req.driverId]
        );

        if (requestCheck.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Request not found or not assigned to you'
            });
        }

        const request = requestCheck.rows[0];

        // Check if request is in a completable state
        if (!['accepted', 'in_progress'].includes(request.status)) {
            return res.status(400).json({
                success: false,
                message: 'Request is not in a completable state'
            });
        }

        // Update request status
        await pool.query(
            `UPDATE cab_requests 
             SET status = 'completed', 
                 completed_at = NOW(),
                 updated_at = NOW()
             WHERE id = $1`,
            [requestId]
        );

        res.json({
            success: true,
            message: 'Ride completed successfully'
        });

    } catch (error) {
        console.error('Complete request error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to complete request',
            error: error.message
        });
    }
});

// RECENT REQUESTS ENDPOINT
router.get('/recent-requests', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                cr.id, 
                cr.pickup_location, 
                cr.dropoff_location, 
                cr.status,
                cr.request_time,
                u.username AS customer_name
             FROM cab_requests cr
             JOIN users u ON cr.user_id = u.id
             WHERE cr.status = 'pending' 
             AND cr.vehicle_type = $1
             AND cr.driver_id IS NULL
             ORDER BY cr.created_at DESC
             LIMIT 10`,
            [req.vehicleType]
        );

        res.json({
            success: true,
            requests: result.rows
        });

    } catch (error) {
        console.error('Recent requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch recent requests',
            error: error.message
        });
    }
});

// PAST RIDES ENDPOINT
router.get('/past-rides', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                cr.id, 
                cr.pickup_location, 
                cr.dropoff_location, 
                cr.fare_amount,
                cr.request_time,
                u.username AS customer_name
             FROM cab_requests cr
             JOIN users u ON cr.user_id = u.id
             WHERE cr.driver_id = $1
             AND cr.status = 'completed'
             ORDER BY cr.completed_at DESC
             LIMIT 10`,
            [req.driverId]
        );

        res.json({
            success: true,
            rides: result.rows
        });

    } catch (error) {
        console.error('Past rides error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch past rides',
            error: error.message
        });
    }
});

// ACCEPT REQUEST ENDPOINT
router.post('/accept-request', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.body;

        // Check if request exists and is available
        const requestCheck = await pool.query(
            `SELECT id FROM cab_requests 
             WHERE id = $1 
             AND status = 'pending' 
             AND driver_id IS NULL`,
            [requestId]
        );

        if (requestCheck.rows.length === 0) {
            return res.status(404).json({
                success: false,
                message: 'Request not available or already assigned'
            });
        }

        // Assign request to driver
        await pool.query(
            `UPDATE cab_requests 
             SET driver_id = $1, 
                 status = 'accepted', 
                 accepted_at = NOW(),
                 updated_at = NOW()
             WHERE id = $2`,
            [req.driverId, requestId]
        );

        res.json({
            success: true,
            message: 'Request accepted successfully'
        });

    } catch (error) {
        console.error('Accept request error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to accept request',
            error: error.message
        });
    }
});

module.exports = router;