const express = require('express');
const router = express.Router();
const auth = require('../../middleware/auth');
const jwt = require('jsonwebtoken');
const config = require('config');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route GET api/auth
// @desc Authenticate users that already exist in the DB
// @access Public
router.get('/', auth, async (req, res) => {
    try {
        const user = await User.findById(req.user.id).select('-password');
        res.json(user);
    } catch (error) {
        console.error(error.message)
        res.status(500).send('Server error');
    }
});

// @route Post api/auth
// @desc Authenticate users that already exist in the DB and get token
// @access Public

router.post('/', [
    // check parameters are not native to express. This is implemented by express-validator and is used to validate the contents of expected fields.
    check('email', 'Please enter a valid email address').isEmail(),
    check('password').exists().withMessage("Password is required")

], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Destructure request body
    const { email, password } = req.body;

    try {
        // See if user exists
        let user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        // Make sure password matches. password being the one the user passed in through the body while user.password being the one that we found when we queried the user email in the DB.
        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.status(400).json({ errors: [{ msg: 'Invalid credentials' }] });
        }

        // Return Json web token
        const payload = {
            user: {
                id: user.id
            }
        }

        jwt.sign(
            payload,
            config.get('jwtToken'),
            { expiresIn: 36000000000 },
            (error, token) => {
                if (error) throw error;
                res.json({ token });
            }
        );
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
