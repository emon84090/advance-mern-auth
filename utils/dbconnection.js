const mongoose = require('mongoose');
require('dotenv').config();

const dbCOnnect = async () => {
    try {
        const data = await mongoose.connect(`mongodb+srv://${process.env.USERNAMEDTI}:${process.env.PASSWORD}@cluster0.dw47wnx.mongodb.net/dtiblood`);
        console.log(`database conected`);
    } catch (err) {
        console.log("not connected")
    }
}


module.exports = dbCOnnect;

