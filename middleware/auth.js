const authenticate = (role) => (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: 'No token provided' });

    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ message: 'Invalid token' });

        // FIX: Only enforce role if one was passed in
        if (role && decoded.role !== role) {
            return res.status(403).json({ message: 'Unauthorized' });
        }

        req.user = decoded;
        next();
    });
};

















// const jwt = require('jsonwebtoken');
// require('dotenv').config();

// const authenticate = (role) => (req, res, next) => {
//     const token = req.headers['authorization']?.split(' ')[1];
//     if (!token) return res.status(401).json({ message: 'No token provided' });

//     jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
//         if (err) return res.status(401).json({ message: 'Invalid token' });
//         if (decoded.role !== role) return res.status(403).json({ message: 'Unauthorized' });
//         req.user = decoded;
//         next();
//     });
// };


// module.exports = { authenticate };
