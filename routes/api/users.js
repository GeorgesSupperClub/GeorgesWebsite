const express = require('express');
const router = express.Router();
const gravatar = require('gravatar');
const bcrypt = require('bcryptjs');
const { check, validationResult } = require('express-validator');

const User = require('../../models/User');

// @route POST api/users
// @desc Register user
// @access Public
router.post('/', [
    // check parameters are not native to express. This is implemented by express-validator and is used to validate the contents of expected fields.
    check('name', 'Name is required').not().isEmpty(),

    check('email', 'Please enter a valid email address').isEmail(),

    check('password')
        .exists().withMessage("Password is required")
        .isLength({ min: 6 }).withMessage("Password must be at least 6 characters in length")
        .matches(/[$-/:-?{-~!"^_`\[\]]/).withMessage("Password must contain at least 1 special character")
        .matches(/.*[A-Z][a-z]/).withMessage("Password must conatin both upper and lower case characters")
        .matches(/.*[0-9]/).withMessage("Password must contain at least one number")

], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }

    // Destructure request body
    const { name, email, password } = req.body;

    try {
        // See if user exists
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ errors: [{ msg: 'User already exists' }] });
        }
        // Get users Gravatar
        const avatar = gravatar.url(email, {
            // Gravatar options to set the size, rating, and default image (when applicable)
            s: '200',
            r: 'pg',
            d: 'mm'
        })

        user = new User({
            name,
            email,
            avatar,
            password
        });

        // Encrypt password using Bcrypt with 10 rounds (recommended per documentation)
        const salt = await bcrypt.genSalt(10);
        user.password = await bcrypt.hash(password, salt);

        await user.save();

        // Return Json web token


        res.send('User registered');
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

module.exports = router;
