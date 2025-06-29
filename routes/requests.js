const express = require('express');
const router = express.Router();
const pool = require('../config/db');
const { authenticate } = require('../middleware/auth');

// Create a new cab request
router.post('/', authenticate('user'), async (req, res) => {
    try {
        const { pickupLocation, dropoffLocation, requestTime } = req.body;
        const userId = req.user.id;

        const result = await pool.query(
            `INSERT INTO cab_requests 
             (user_id, pickup_location, dropoff_location, request_time, status) 
             VALUES ($1, $2, $3, $4, 'PENDING') 
             RETURNING *`,
            [userId, pickupLocation, dropoffLocation, requestTime || new Date()]
        );

        res.status(201).json({
            success: true,
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error creating request:', error);
        res.status(400).json({ 
            success: false,
            message: error.message 
        });
    }
});

// // Get user's cab requests
// router.get('/', authenticate('user'), async (req, res) => {
//     try {
//         const userId = req.user.id;
        
//         const result = await pool.query(
//             `SELECT cr.*, 
//                     d.id as driver_id, 
//                     d.name as driver_name,
//                     d.vehicle_type,
                    
//                     d.vehicle_number
//              FROM cab_requests cr
//              LEFT JOIN drivers d ON cr.driver_id = d.id
//              WHERE cr.user_id = $1
//              ORDER BY cr.request_time DESC`,
//             [userId]
//         );

// Get user's cab requests
router.get('/', authenticate('user'), async (req, res) => {
    try {
        const userId = req.user.id;
        
        const result = await pool.query(
            `SELECT cr.*, 
                    d.id as driver_id, 
                    d.name as driver_name,
                    d.phone,
                    d.vehicle_number
             FROM cab_requests cr
             LEFT JOIN drivers d ON cr.driver_id = d.id
             WHERE cr.user_id = $1
             ORDER BY cr.request_time DESC`,
            [userId]
        );
        res.json({
            success: true,
            data: result.rows.map(row => ({
                id: row.id,
                pickup_location: row.pickup_location,
                dropoff_location: row.dropoff_location,
                request_time: row.request_time,
                status: row.status,
                driver: row.driver_id ? {
                    id: row.driver_id,
                    name: row.driver_name,
                    vehicle_type: row.vehicle_type,
                    vehicle_number: row.vehicle_number
                } : null
            }))
        });
    } catch (error) {
        console.error('Error fetching requests:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error fetching requests' 
        });
    }
});

// Get all requests for admin
router.get('/all', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT cr.*, 
                    u.username as user_name,
                    d.name as driver_name
             FROM cab_requests cr
             JOIN users u ON cr.user_id = u.id
             LEFT JOIN drivers d ON cr.driver_id = d.id
             ORDER BY cr.request_time DESC`
        );

        res.json({
            success: true,
            data: result.rows
        });
    } catch (error) {
        console.error('Error fetching all requests:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error fetching requests' 
        });
    }
});

// Assign driver to request
router.put('/:id/assign', authenticate('admin'), async (req, res) => {
    try {
        const { driverId } = req.body;
        const requestId = req.params.id;

        await pool.query('BEGIN');

        // Assign driver
        await pool.query(
            `UPDATE cab_requests 
             SET driver_id = $1, status = 'ASSIGNED' 
             WHERE id = $2 RETURNING *`,
            [driverId, requestId]
        );

        // Mark driver as unavailable
        await pool.query(
            `UPDATE drivers 
             SET available = false 
             WHERE id = $1`,
            [driverId]
        );

        await pool.query('COMMIT');

        res.json({
            success: true,
            message: 'Driver assigned successfully'
        });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Error assigning driver:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error assigning driver' 
        });
    }
});

module.exports = router;