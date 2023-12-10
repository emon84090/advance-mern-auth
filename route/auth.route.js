const errorhandle = require("../utils/errorhandle");
const { generateToken } = require("../utils/generatetoken");
const { verifyjwt } = require("../utils/verifyjwt");
const bcrypt = require("bcrypt");
const sendmail = require("../utils/sendmail");
const Router = require("express").Router();
const mongoose = require("mongoose");
const { rateLimit } = require("express-rate-limit");
const users = require("../model/users");
require("dotenv").config();

const limiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  limit: 3,
  message: "Too Many Request from This Ip Try Agin After 2 Minutes",
});

Router.post("/signup", limiter, async (req, res, next) => {
  const { name, email, password } = req.body;

  try {
    const useremail = await users.findOne({ email: email });

    if (useremail) {
      return res.status(401).json({
        status: false,
        message: "email already registared",
      });
    }
    const data = {
      name: name,
      email: email,
      password: password,
    };

    const user = await users.create(data);
    const token = user.vaificationToken();
    await user.save({ validateBeforeSave: false });

    sendmail(
      user.email,
      "Acount Verification",
      `${process.env.CLIENT_VERIFICATION_URL}/${token}`
    );
    res.status(200).json({
      status: true,
      message: "Successfully Signed Up,Please Verify Your Email",
    });
  } catch (err) {
    res.status(400).json({
      status: false,
      error: err.message,
    });
  }
});

Router.post("/resendtoken", limiter, async (req, res, next) => {
  const { email } = req.body;

  try {
    const useremail = await users.findOne({ email: email });

    const token = useremail.vaificationToken();
    await useremail.save({ validateBeforeSave: false });

    sendmail(
      useremail.email,
      "Acount Verification",
      `http://localhost:5173/confirmacount/${token}`
    );
    res.status(200).json({
      status: true,
      message: `Verify Link Send Success ${email}`,
    });
  } catch (err) {
    res.status(400).json({
      status: false,
      error: err.message,
    });
  }
});

Router.patch("/activeacount/:token", async (req, res, next) => {
  try {
    const findToken = await users.findOne({
      confirmationToken: req.params.token,
    });
    if (findToken === null) {
      return errorhandle("invalid token", 403);
    }

    const expired = new Date() > new Date(findToken.confirmationTokenExpirese);
    if (expired) {
      return errorhandle("acount verification token expired", 401);
    }
    findToken.emailverified = true;
    // findToken.confirmationToken = undefined;
    // findToken.confirmationTokenExpirese = undefined;

    findToken.save({ validateBeforeSave: false });

    res.status(200).send({
      status: true,
      message: "your acount has been actived",
    });
  } catch (err) {
    return next(err);
  }
});

Router.post("/login", limiter, async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const useremail = await users.findOne({ email: email });
    if (!useremail) {
      return errorhandle("email not registared", 401);
    }

    if (useremail.lockedUntil && useremail.lockedUntil > new Date()) {
      return res.status(423).json({
        message: "Account locked. Try again 2 hour later.",
        time: useremail?.lockedUntil,
      });
    }

    const isvalidPassword = useremail.comparePassword(
      password,
      useremail.password
    );

    if (!isvalidPassword) {
      useremail.failedLoginAttempts += 1;

      if (useremail.failedLoginAttempts >= 4) {
        // Lock the account for 2 hours
        useremail.lockedUntil = new Date(Date.now() + 2 * 60 * 60 * 1000);
        useremail.failedLoginAttempts = 0;

        await useremail.save();
        return res.status(401).json({
          message: "Well Done , Your Acount Lock for 2 hour",
        });
      }
      useremail.lockedUntil = undefined;
      await useremail.save({ validateBeforeSave: false });

      return res.status(401).json({
        message: "Email Or Password Wrong",
        attempts: useremail.failedLoginAttempts,
      });
    }
    useremail.failedLoginAttempts = 0;
    useremail.save();
    const token = generateToken(useremail);

    res.status(200).json({
      status: true,
      message: "login success",
      token: token,
      data: useremail,
    });
  } catch (err) {
    next(err);
  }
});

Router.get("/me", verifyjwt, async (req, res, next) => {
  try {
    const { email } = req.user;
    const result = await users
      .findOne({ email: email })
      .select("name email emailverified");
    res.status(200).send({
      status: true,
      user: result,
    });
  } catch (err) {
    next(err);
  }
});

Router.patch("/changepassword", limiter, verifyjwt, async (req, res, next) => {
  try {
    const { email, password } = req.body;
    const useremail = await users.findOne({ email: email });
    if (!useremail) {
      return errorhandle("email not registared", 401);
    }

    const hasedpassword = bcrypt.hashSync(password, 10);

    const result = await users.updateOne(
      { email: email },
      { $set: { password: hasedpassword } }
    );
    if (!result.modifiedCount) {
      return errorhandle("password updated faild,try again", 400);
    }

    res.status(200).json({
      status: true,
      message: "password  uupdated success",
    });
  } catch (err) {
    next(err);
  }
});

Router.post("/forgetpassword", limiter, async (req, res, next) => {
  const { email } = req.query;
  const session = await mongoose.startSession();

  try {
    session.startTransaction();
    if (!email) {
      return errorhandle("Email required", 400);
    }

    const getUsers = await users.findOne({ email: email });
    if (!getUsers) {
      return errorhandle("Email Not Registared", 400);
    }

    const token = getUsers.passwordReset();

    sendmail(getUsers.email, "Password Reset Otp", token);

    await getUsers.save({ validateBeforeSave: false });

    await session.commitTransaction();
    session.endSession();

    res.status(200).send({
      status: true,
      message: "chek your email",
    });
  } catch (err) {
    await session.abortTransaction();
    session.endSession();
    next(err);
  }
});

Router.patch("/resetpassword", limiter, async (req, res, next) => {
  try {
    const token = req.query.token;

    if (!token) {
      return errorhandle("Token required", 400);
    }
    const findToken = await users.findOne({ passwordResetToken: token });

    if (!findToken) {
      return errorhandle("Invalid OTP", 400);
    }
    const expired = new Date() > new Date(findToken.passwordResetExpirise);
    if (expired) {
      return errorhandle("OTP Expired,Try again", 403);
    }

    const hash = bcrypt.hashSync(req.body.password, 10);

    const result = await users.updateOne(
      { passwordResetToken: token },
      { $set: { password: hash } }
    );

    if (result.matchedCount) {
      findToken.passwordResetToken = "";

      await findToken.save({ validateBeforeSave: false });
      res.status(200).send({
        status: true,
        message: "password reset success",
      });
    }
  } catch (err) {
    next(err);
  }
});

module.exports = Router;
