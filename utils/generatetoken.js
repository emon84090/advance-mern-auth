const jwt = require('jsonwebtoken');
require('dotenv').config();
module.exports.generateToken = (userinfo) => {
    const payload = {
        email: userinfo.email,

    }

    const token = jwt.sign(payload, process.env.SECCRET_KEY, {
        expiresIn: '7days'
    })

    return token
}