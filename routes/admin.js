const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('../config/db');
const { authenticate } = require('../middleware/auth');
const { Parser } = require('json2csv');
const validator = require('validator');

// Admin login
router.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        if (!username || !password) {
            return res.status(400).json({ message: 'Username and password are required' });
        }
        if (!process.env.JWT_SECRET) {
            console.error('JWT_SECRET is not defined');
            return res.status(500).json({ message: 'Server configuration error' });
        }
        const result = await pool.query('SELECT * FROM admins WHERE LOWER(username) = LOWER($1)', [username]);
        const admin = result.rows[0];
        if (!admin) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        // Check if password is a valid bcrypt hash
        if (!admin.password || !admin.password.startsWith('$2b$')) {
            console.error(`Invalid password hash for admin ${admin.id}`);
            return res.status(500).json({ message: 'Invalid server data' });
        }
        const isValidPassword = await bcrypt.compare(password, admin.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid username or password' });
        }
        if (!admin.id) {
            console.error(`Admin ${username} has no ID`);
            return res.status(500).json({ message: 'Invalid server data' });
        }
        const token = jwt.sign(
            { id: admin.id, role: 'admin', username: admin.username },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );
        res.json({ token, username: admin.username, message: 'Admin login successful' });
    } catch (error) {
        console.error('Login error:', error.stack);
        res.status(500).json({ message: 'Error logging in', error: error.message });
    }
});

// Admin logout
router.post('/logout', authenticate('admin'), async (req, res) => {
    try {
        res.json({ message: 'Logout successful' });
    } catch (error) {
        console.error('Logout error:', error.stack);
        res.status(500).json({ message: 'Error logging out', error: error.message });
    }
});

// Ride requests
router.get('/requests', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT r.id, r.user_id, r.driver_id, r.pickup_location, r.dropoff_location, r.status, r.fare_amount,
                   r.created_at, u.name AS user_name, u.gender AS user_gender,
                   d.name AS driver_name
            FROM cab_requests r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN drivers d ON r.driver_id = d.id
            ORDER BY r.created_at DESC
        `);
        res.json({ data: result.rows, message: 'Ride requests fetched successfully' });
    } catch (error) {
        console.error('Error fetching ride requests:', error.stack);
        res.status(500).json({ message: 'Error fetching ride requests', error: error.message });
    }
});

// Get single ride request
router.get('/requests/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid request ID' });
        }
        const result = await pool.query(`
            SELECT r.id, r.user_id, r.driver_id, r.pickup_location, r.dropoff_location, r.status, r.fare_amount,
                   r.created_at, u.name AS user_name, u.gender AS user_gender,
                   d.name AS driver_name
            FROM cab_requests r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN drivers d ON r.driver_id = d.id
            WHERE r.id = $1
        `, [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Ride request not found' });
        }
        res.json({ data: result.rows[0], message: 'Ride request fetched successfully' });
    } catch (error) {
        console.error('Error fetching ride request:', error.stack);
        res.status(500).json({ message: 'Error fetching ride request', error: error.message });
    }
});

// Assign driver to ride request
router.put('/requests/:id/assign', authenticate('admin'), async (req, res) => {
    const { driver_id } = req.body;
    const { id } = req.params;
    try {
        if (!validator.isInt(id) || !validator.isInt(driver_id)) {
            return res.status(400).json({ message: 'Invalid request ID or driver ID' });
        }
        if (!driver_id) {
            return res.status(400).json({ message: 'Driver ID is required' });
        }
        const requestCheck = await pool.query(
            'SELECT * FROM cab_requests WHERE id = $1 AND status = $2',
            [id, 'PENDING']
        );
        if (requestCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Ride request not found or not in PENDING status' });
        }
        const driverCheck = await pool.query(
            'SELECT * FROM drivers WHERE id = $1 AND available = $2',
            [driver_id, true]
        );
        if (driverCheck.rows.length === 0) {
            return res.status(404).json({ message: 'Driver not found or not available' });
        }
        await pool.query('BEGIN');
        const updateRequest = await pool.query(
            'UPDATE cab_requests SET driver_id = $1, status = $2, updated_at = NOW() WHERE id = $3 RETURNING *',
            [driver_id, 'CONFIRMED', id]
        );
        await pool.query('UPDATE drivers SET available = $1, updated_at = NOW() WHERE id = $2', [false, driver_id]);
        await pool.query('COMMIT');
        res.json({ data: updateRequest.rows[0], message: 'Driver assigned successfully' });
    } catch (error) {
        await pool.query('ROLLBACK');
        console.error('Error assigning driver:', error.stack);
        res.status(500).json({ message: 'Error assigning driver', error: error.message });
    }
});

// Drivers
router.get('/drivers', authenticate('admin'), async (req, res) => {
    try {
        const { available } = req.query;
        let query = 'SELECT id, name, email, phone, vehicle_type, vehicle_number, available, gender FROM drivers ORDER BY name';
        let params = [];
        if (available) {
            if (!['true', 'false'].includes(available)) {
                return res.status(400).json({ message: 'Invalid available parameter' });
            }
            query = 'SELECT id, name, email, phone, vehicle_type, vehicle_number, available, gender FROM drivers WHERE available = $1 ORDER BY name';
            params = [available === 'true'];
        }
        const result = await pool.query(query, params);
        res.json({ data: result.rows, message: 'Drivers fetched successfully' });
    } catch (error) {
        console.error('Error fetching drivers:', error.stack);
        res.status(500).json({ message: 'Error fetching drivers', error: error.message });
    }
});

router.get('/drivers/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid driver ID' });
        }
        const result = await pool.query(
            'SELECT id, name, email, phone, vehicle_type, vehicle_number, available, gender FROM drivers WHERE id = $1',
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Driver not found' });
        }
        res.json({ data: result.rows[0], message: 'Driver fetched successfully' });
    } catch (error) {
        console.error('Error fetching driver:', error.stack);
        res.status(500).json({ message: 'Error fetching driver', error: error.message });
    }
});

router.post('/drivers', authenticate('admin'), async (req, res) => {
    const { name, email, phone, vehicle_type, vehicle_number, available, gender } = req.body;
    try {
        if (!name || !email || !phone || !vehicle_type || !vehicle_number) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        if (!validator.isEmail(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }
        if (!validator.isMobilePhone(phone, 'any')) {
            return res.status(400).json({ message: 'Invalid phone number' });
        }
        if (!['men', 'women', 'other'].includes(gender || 'men')) {
            return res.status(400).json({ message: 'Invalid gender' });
        }
        const result = await pool.query(
            'INSERT INTO drivers (name, email, phone, vehicle_type, vehicle_number, available, gender, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW()) RETURNING *',
            [name, email, phone, vehicle_type, vehicle_number, available !== false, gender || 'men']
        );
        res.status(201).json({ data: result.rows[0], message: 'Driver added successfully' });
    } catch (error) {
        console.error('Error adding driver:', error.stack);
        if (error.code === '23505') {
            return res.status(400).json({ message: 'Email already exists' });
        }
        res.status(500).json({ message: 'Error adding driver', error: error.message });
    }
});

router.put('/drivers/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    const { name, email, phone, vehicle_type, vehicle_number, available, gender } = req.body;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid driver ID' });
        }
        let query = 'UPDATE drivers SET updated_at = NOW()';
        const params = [];
        let paramIndex = 1;

        if (name) {
            query += `, name = $${paramIndex++}`;
            params.push(name);
        }
        if (email) {
            if (!validator.isEmail(email)) {
                return res.status(400).json({ message: 'Invalid email format' });
            }
            query += `, email = $${paramIndex++}`;
            params.push(email);
        }
        if (phone) {
            if (!validator.isMobilePhone(phone, 'any')) {
                return res.status(400).json({ message: 'Invalid phone number' });
            }
            query += `, phone = $${paramIndex++}`;
            params.push(phone);
        }
        if (vehicle_type) {
            query += `, vehicle_type = $${paramIndex++}`;
            params.push(vehicle_type);
        }
        if (vehicle_number) {
            query += `, vehicle_number = $${paramIndex++}`;
            params.push(vehicle_number);
        }
        if (available !== undefined) {
            query += `, available = $${paramIndex++}`;
            params.push(available);
        }
        if (gender) {
            if (!['men', 'women', 'other'].includes(gender)) {
                return res.status(400).json({ message: 'Invalid gender' });
            }
            query += `, gender = $${paramIndex++}`;
            params.push(gender);
        }

        query += ` WHERE id = $${paramIndex} RETURNING *`;
        params.push(id);

        if (params.length === 1) {
            return res.status(400).json({ message: 'No fields provided for update' });
        }

        const result = await pool.query(query, params);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Driver not found' });
        }
        res.json({ data: result.rows[0], message: 'Driver updated successfully' });
    } catch (error) {
        console.error('Error updating driver:', error.stack);
        if (error.code === '23505') {
            return res.status(400).json({ message: 'Email already exists' });
        }
        res.status(500).json({ message: 'Error updating driver', error: error.message });
    }
});

router.delete('/drivers/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid driver ID' });
        }
        const result = await pool.query('DELETE FROM drivers WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'Driver not found' });
        }
        res.json({ message: 'Driver deleted successfully' });
    } catch (error) {
        console.error('Error deleting driver:', error.stack);
        res.status(500).json({ message: 'Error deleting driver', error: error.message });
    }
});

// Users management
router.get('/users', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, phone, gender, created_at FROM users ORDER BY created_at DESC'
        );
        res.json({ data: result.rows, message: 'Users fetched successfully' });
    } catch (error) {
        console.error('Error fetching users:', error.stack);
        res.status(500).json({ message: 'Error fetching users', error: error.message });
    }
});

router.get('/users/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid user ID' });
        }
        const result = await pool.query(
            'SELECT id, name, email, phone, gender, created_at FROM users WHERE id = $1',
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ data: result.rows[0], message: 'User fetched successfully' });
    } catch (error) {
        console.error('Error fetching user:', error.stack);
        res.status(500).json({ message: 'Error fetching user', error: error.message });
    }
});

router.delete('/users/:id', authenticate('admin'), async (req, res) => {
    const { id } = req.params;
    try {
        if (!validator.isInt(id)) {
            return res.status(400).json({ message: 'Invalid user ID' });
        }
        const result = await pool.query('DELETE FROM users WHERE id = $1 RETURNING *', [id]);
        if (result.rows.length === 0) {
            return res.status(404).json({ message: 'User not found' });
        }
        res.json({ message: 'User deleted successfully' });
    } catch (error) {
        console.error('Error deleting user:', error.stack);
        res.status(500).json({ message: 'Error deleting user', error: error.message });
    }
});

// Analytics
router.get('/analytics', authenticate('admin'), async (req, res) => {
    try {
        const requests = await pool.query(`
            SELECT DATE_TRUNC('day', created_at) AS date, COUNT(*) AS count, SUM(fare_amount) AS revenue
            FROM cab_requests
            GROUP BY DATE_TRUNC('day', created_at)
            ORDER BY date DESC
            LIMIT 30
        `);
        const drivers = await pool.query(`
            SELECT d.name, COUNT(r.id) AS trips, SUM(r.fare_amount) AS earnings
            FROM drivers d
            LEFT JOIN cab_requests r ON d.id = r.driver_id AND r.status = 'COMPLETED'
            GROUP BY d.id, d.name
            ORDER BY trips DESC
            LIMIT 10
        `);
        res.json({
            data: {
                requests: requests.rows,
                drivers: drivers.rows
            },
            message: 'Analytics data fetched successfully'
        });
    } catch (error) {
        console.error('Error fetching analytics:', error.stack);
        res.status(500).json({ message: 'Error fetching analytics', error: error.message });
    }
});

// Live tracking
router.get('/live-tracking', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT r.id, r.user_id, r.driver_id, r.status, r.current_location,
                   u.name AS user_name, d.name AS driver_name
            FROM cab_requests r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN drivers d ON r.driver_id = d.id
            WHERE r.status IN ('CONFIRMED', 'IN_PROGRESS')
        `);
        res.json({ data: result.rows, message: 'Live tracking data fetched successfully' });
    } catch (error) {
        console.error('Error fetching live tracking data:', error.stack);
        res.status(500).json({ message: 'Error fetching live tracking data', error: error.message });
    }
});

// Settings
router.get('/settings', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM system_settings WHERE id = 1');
        const defaultSettings = {
            id: 1,
            base_fare: 5.00,
            price_per_mile: 1.50,
            price_per_minute: 0.50,
            maintenance_mode: false,
            enable_notifications: true
        };
        res.json({ data: result.rows[0] || defaultSettings, message: 'Settings fetched successfully' });
    } catch (error) {
        console.error('Error fetching settings:', error.stack);
        res.status(500).json({ message: 'Error fetching settings', error: error.message });
    }
});

router.put('/settings/pricing', authenticate('admin'), async (req, res) => {
    const { base_fare, price_per_mile, price_per_minute } = req.body;
    try {
        if (base_fare == null || price_per_mile == null || price_per_minute == null) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        if (!validator.isFloat(base_fare.toString(), { min: 0 }) ||
            !validator.isFloat(price_per_mile.toString(), { min: 0 }) ||
            !validator.isFloat(price_per_minute.toString(), { min: 0 })) {
            return res.status(400).json({ message: 'Invalid pricing values' });
        }
        const result = await pool.query(
            'INSERT INTO system_settings (id, base_fare, price_per_mile, price_per_minute, created_at, updated_at) VALUES (1, $1, $2, $3, NOW(), NOW()) ' +
            'ON CONFLICT (id) DO UPDATE SET base_fare = $1, price_per_mile = $2, price_per_minute = $3, updated_at = NOW() RETURNING *',
            [parseFloat(base_fare), parseFloat(price_per_mile), parseFloat(price_per_minute)]
        );
        res.json({ data: result.rows[0], message: 'Pricing settings updated successfully' });
    } catch (error) {
        console.error('Error updating pricing settings:', error.stack);
        res.status(500).json({ message: 'Error updating pricing settings', error: error.message });
    }
});

router.put('/settings/system', authenticate('admin'), async (req, res) => {
    const { maintenance_mode, enable_notifications } = req.body;
    try {
        if (maintenance_mode == null || enable_notifications == null) {
            return res.status(400).json({ message: 'Missing required fields' });
        }
        if (typeof maintenance_mode !== 'boolean' || typeof enable_notifications !== 'boolean') {
            return res.status(400).json({ message: 'Invalid boolean values' });
        }
        const result = await pool.query(
            'INSERT INTO system_settings (id, maintenance_mode, enable_notifications, created_at, updated_at) VALUES (1, $1, $2, NOW(), NOW()) ' +
            'ON CONFLICT (id) DO UPDATE SET maintenance_mode = $1, enable_notifications = $2, updated_at = NOW() RETURNING *',
            [maintenance_mode, enable_notifications]
        );
        res.json({ data: result.rows[0], message: 'System settings updated successfully' });
    } catch (error) {
        console.error('Error updating system settings:', error.stack);
        res.status(500).json({ message: 'Error updating system settings', error: error.message });
    }
});

// Export data
router.get('/requests/export', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT r.id, r.user_id, u.name AS user_name, r.pickup_location, r.dropoff_location,
                   d.name AS driver_name, r.status, r.fare_amount, r.created_at
            FROM cab_requests r
            LEFT JOIN users u ON r.user_id = u.id
            LEFT JOIN drivers d ON r.driver_id = d.id
            ORDER BY r.created_at DESC
        `);
        const fields = ['id', 'user_name', 'pickup_location', 'dropoff_location', 'driver_name', 'status', 'fare_amount', 'created_at'];
        const parser = new Parser({ fields });
        const csv = parser.parse(result.rows);
        res.header('Content-Type', 'text/csv');
        res.attachment('requests-export.csv');
        res.send(csv);
    } catch (error) {
        console.error('Error exporting requests:', error.stack);
        res.status(500).json({ message: 'Error exporting requests', error: error.message });
    }
});

router.get('/users/export', authenticate('admin'), async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, name, email, phone, gender, created_at FROM users ORDER BY created_at DESC'
        );
        const fields = ['id', 'name', 'email', 'phone', 'gender', 'created_at'];
        const parser = new Parser({ fields });
        const csv = parser.parse(result.rows);
        res.header('Content-Type', 'text/csv');
        res.attachment('users-export.csv');
        res.send(csv);
    } catch (error) {
        console.error('Error exporting users:', error.stack);
        res.status(500).json({ message: 'Error exporting users', error: error.message });
    }
});

router.get('/dashboard/export', authenticate('admin'), async (req, res) => {
    try {
        // Fetch summary stats
        const summaryStats = await pool.query(`
            SELECT 
                COUNT(*) AS total_rides,
                SUM(CASE WHEN status = 'PENDING' THEN 1 ELSE 0 END) AS pending_requests,
                SUM(CASE WHEN status = 'COMPLETED' THEN fare_amount ELSE 0 END) AS revenue,
                (SELECT COUNT(*) FROM drivers) AS total_drivers,
                (SELECT COUNT(*) FROM drivers WHERE available = true) AS active_drivers
            FROM cab_requests
        `);

        // Fetch active drivers details
        const activeDrivers = await pool.query(`
            SELECT id, name, vehicle_type, vehicle_number, phone
            FROM drivers
            WHERE available = true
            ORDER BY name
        `);

        // Fetch pending requests details
        const pendingRequests = await pool.query(`
            SELECT r.id, r.pickup_location, r.dropoff_location, u.name AS user_name, r.status, r.created_at
            FROM cab_requests r
            LEFT JOIN users u ON r.user_id = u.id
            WHERE r.status = 'PENDING'
            ORDER BY r.created_at DESC
        `);

        // Structure the CSV data
        const csvData = [];

        // Add summary stats
        csvData.push({
            section: 'Summary Stats',
            total_rides: summaryStats.rows[0].total_rides,
            pending_requests: summaryStats.rows[0].pending_requests,
            revenue: parseFloat(summaryStats.rows[0].revenue || 0).toFixed(2),
            total_drivers: summaryStats.rows[0].total_drivers,
            active_drivers: summaryStats.rows[0].active_drivers
        });

        // Add separator
        csvData.push({ section: '' });

        // Add active drivers header
        csvData.push({
            section: 'Active Drivers',
            id: 'ID',
            name: 'Name',
            vehicle_type: 'Vehicle Type',
            vehicle_number: 'Vehicle Number',
            phone: 'Phone'
        });

        // Add active drivers data
        activeDrivers.rows.forEach(driver => {
            csvData.push({
                section: '',
                id: driver.id,
                name: driver.name,
                vehicle_type: driver.vehicle_type,
                vehicle_number: driver.vehicle_number,
                phone: driver.phone
            });
        });

        // Add separator
        csvData.push({ section: '' });

        // Add pending requests header
        csvData.push({
            section: 'Pending Requests',
            id: 'ID',
            pickup_location: 'Pickup Location',
            dropoff_location: 'Dropoff Location',
            user_name: 'User Name',
            status: 'Status',
            created_at: 'Created At'
        });

        // Add pending requests data
        pendingRequests.rows.forEach(request => {
            csvData.push({
                section: '',
                id: request.id,
                pickup_location: request.pickup_location,
                dropoff_location: request.dropoff_location,
                user_name: request.user_name || 'N/A',
                status: request.status,
                created_at: request.created_at ? new Date(request.created_at).toISOString() : 'N/A'
            });
        });

        // Define fields for CSV
        const fields = [
            { label: 'Section', value: 'section' },
            { label: 'Total Rides', value: 'total_rides' },
            { label: 'Pending Requests', value: 'pending_requests' },
            { label: 'Revenue', value: 'revenue' },
            { label: 'Total Drivers', value: 'total_drivers' },
            { label: 'Active Drivers', value: 'active_drivers' },
            { label: 'Driver ID', value: 'id' },
            { label: 'Driver Name', value: 'name' },
            { label: 'Vehicle Type', value: 'vehicle_type' },
            { label: 'Vehicle Number', value: 'vehicle_number' },
            { label: 'Phone', value: 'phone' },
            { label: 'Request ID', value: 'id' },
            { label: 'Pickup Location', value: 'pickup_location' },
            { label: 'Dropoff Location', value: 'dropoff_location' },
            { label: 'User Name', value: 'user_name' },
            { label: 'Status', value: 'status' },
            { label: 'Created At', value: 'created_at' }
        ];

        const parser = new Parser({ fields });
        const csv = parser.parse(csvData);
        res.header('Content-Type', 'text/csv');
        res.attachment('dashboard-export.csv');
        res.send(csv);
    } catch (error) {
        console.error('Error exporting dashboard:', error.stack);
        res.status(500).json({ message: 'Error exporting dashboard', error: error.message });
    }
});

module.exports = router;