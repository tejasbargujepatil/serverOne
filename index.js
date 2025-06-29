const express = require('express');
     const path = require('path');
     const cors = require('cors');
     require('dotenv').config(); // Load .env variables

     const userRoutes = require('./routes/user');
     const adminRoutes = require('./routes/admin');
     const requestRoutes = require('./routes/requests');
     const driverRoutes = require('./routes/drivers');


     const app = express();
     const PORT = process.env.PORT || 3000;

     app.use(cors());
     app.use(express.json());
     app.use(express.static(path.join(__dirname, '../client'))); // Serve frontend

     app.use('/api/user', userRoutes);
     app.use('/api/admin', adminRoutes);
     app.use('/api/requests', requestRoutes);
     app.use('/api/drivers', driverRoutes);
     app.use('/admin', adminRoutes);
     

     app.listen(PORT, () => {
         console.log(`Server running on port ${PORT}`);
     });