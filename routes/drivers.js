const express = require('express');
const router = express.Router();
const pool = require('../config/db');
const { authenticate } = require('../middleware/auth');

// Get driver details
router.get('/:id', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM drivers WHERE id = $1',
            [req.params.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Driver not found' });
        }

        res.json(result.rows[0]);
    } catch (error) {
        res.status(500).json({ message: error.message });
    }
});

// Add a new driver
router.post('/', authenticate('admin'), async (req, res) => {
    try {
        const { name, phone, vehicle_type, vehicle_number, available } = req.body;

        const result = await pool.query(
            `INSERT INTO drivers (name, phone, vehicle_type, vehicle_number, available) 
             VALUES ($1, $2, $3, $4, $5) RETURNING *`,
            [name, phone, vehicle_type, vehicle_number, available]
        );

        res.status(201).json({
            success: true,
            data: result.rows[0]
        });
    } catch (error) {
        console.error('Error adding driver:', error);
        res.status(500).json({ 
            success: false,
            message: 'Error adding driver' 
        });
    }
});

module.exports = router;