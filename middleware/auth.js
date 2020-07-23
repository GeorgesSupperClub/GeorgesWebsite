const jwt = require('jsonwebtoken');
const config = require('config');

// Middleware here is just a fucntion that has access to the request and response and has a callback to pass along to the next piece of midddleware.
module.exports = function (req, res, next) {
    // Get token from header
    const token = req.header('x-auth-token');

    // Check for token
    if (!token) {
        return res.status(401).json({ msg: 'Authorization denied' });
    }

    // Verify token
    try {
        const decoded = jwt.verify(token, config.get('jwtToken'));
        req.user = decoded.user;
        next();
    } catch (error) {
        res.status(401).json({ msg: 'Invalid token' });
    }
}