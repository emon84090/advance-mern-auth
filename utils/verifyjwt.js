const jwt = require("jsonwebtoken");
const { promisify } = require("util");
const errorhandle = require("./errorhandle");

require('dotenv').config();
module.exports.verifyjwt = async (req, res, next) => {
    try {

        const token = req.headers?.authorization?.split(" ")?.[1];

        if (!token) {
            return errorhandle("authentication required", 401)
        }

        const decoded = await promisify(jwt.verify)(token, process.env.SECCRET_KEY);

        req.user = decoded;
        next();

    } catch (err) {

        next(err)
    }
}