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

router.post('/register', async (req, res) => {
    try {
        const { name, email, phone, vehicle_type, vehicle_number, password, license_number } = req.body;

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

        const hashedPassword = await bcrypt.hash(password, 10);

        const newDriver = await pool.query(
            `INSERT INTO drivers 
             (name, email, phone, vehicle_type, vehicle_number, password, license_number)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING id, name, email, phone, vehicle_type, vehicle_number, license_number, is_online`,
            [name, email, phone, vehicle_type, vehicle_number, hashedPassword, license_number || 'PENDING']
        );

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

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

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
        const isMatch = await bcrypt.compare(password, driver.password);

        if (!isMatch) {
            return res.status(401).json({
                success: false,
                message: 'Invalid email or password'
            });
        }

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
                vehicle_number: driver.vehicle_number,
                license_number: driver.license_number,
                is_online: driver.is_online
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

router.get('/profile', verifyToken, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT 
                id, name, email, phone, 
                vehicle_type, vehicle_number, 
                license_number, is_online,
                current_latitude, current_longitude
             FROM drivers WHERE id = $1`,
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

router.post('/location', verifyToken, async (req, res) => {
    try {
        const { current_latitude, current_longitude, location_accuracy, is_online } = req.body;

        if (current_latitude === undefined || current_longitude === undefined) {
            return res.status(400).json({
                success: false,
                message: 'Latitude and longitude are required'
            });
        }

        await pool.query(
            `UPDATE drivers 
             SET 
                current_latitude = $1,
                current_longitude = $2,
                location_accuracy = $3,
                last_location_update = NOW(),
                is_online = $4,
                updated_at = NOW()
             WHERE id = $5`,
            [current_latitude, current_longitude, location_accuracy, is_online, req.driverId]
        );

        res.json({
            success: true,
            message: 'Location updated successfully'
        });

    } catch (error) {
        console.error('Location update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update location',
            error: error.message
        });
    }
});

router.post('/status', verifyToken, async (req, res) => {
    try {
        const { is_online } = req.body;

        await pool.query(
            `UPDATE drivers 
             SET 
                is_online = $1,
                last_seen = NOW(),
                updated_at = NOW()
             WHERE id = $2`,
            [is_online, req.driverId]
        );

        res.json({
            success: true,
            message: 'Status updated successfully'
        });

    } catch (error) {
        console.error('Status update error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to update status',
            error: error.message
        });
    }
});

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
                u.phone AS phone,
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

router.post('/complete-request', verifyToken, async (req, res) => {
    try {
        const { requestId } = req.body;

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

        if (!['accepted', 'in_progress'].includes(request.status)) {
            return res.status(400).json({
                success: false,
                message: 'Request is not in a completable state'
            });
        }

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

router.get('/nearby-requests', verifyToken, async (req, res) => {
    try {
        const { lat, lng, radius = 5000 } = req.query;
        
        if (!lat || !lng) {
            return res.status(400).json({
                success: false,
                message: 'Latitude and longitude are required'
            });
        }

        const result = await pool.query(
            `SELECT 
                cr.id,
                cr.pickup_location,
                cr.dropoff_location,
                cr.status,
                cr.request_time,
                u.username AS customer_name,
                u.phone AS customer_phone,
                ST_Distance(
                    ST_SetSRID(ST_MakePoint($1, $2), 4326),
                    ST_SetSRID(ST_MakePoint(cr.pickup_lng, cr.pickup_lat), 4326)
                ) AS distance
             FROM cab_requests cr
             JOIN users u ON cr.user_id = u.id
             WHERE cr.status = 'pending'
             AND cr.vehicle_type = $3
             AND cr.driver_id IS NULL
             AND ST_DWithin(
                ST_SetSRID(ST_MakePoint($1, $2),
                ST_SetSRID(ST_MakePoint(cr.pickup_lng, cr.pickup_lat),
                $4
             )
             ORDER BY cr.created_at ASC
             LIMIT 20`,
            [lng, lat, req.vehicleType, radius]
        );

        res.json({
            success: true,
            requests: result.rows
        });

    } catch (error) {
        console.error('Nearby requests error:', error);
        res.status(500).json({
            success: false,
            message: 'Failed to fetch nearby requests',
            error: error.message
        });
    }
});

module.exports = router;