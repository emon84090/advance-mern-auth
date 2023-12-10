const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const crypto = require("crypto");

const userlistSchema = mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "name must required"],
    },

    email: {
      type: String,
      required: [true, "email must required"],
    },

    password: {
      type: String,
      required: [true, "password must required"],
    },
    emailverified: {
      type: Boolean,
      default: false,
      enum: [true, false],
    },
    confirmationToken: String,
    confirmationTokenExpirese: Date,
    passwordResetToken: String,
    passwordResetExpirise: Date,
    failedLoginAttempts: {
      type: Number,
      default: 0,
    },
    lockedUntil: Date,
  },
  {
    timestamps: true,
  }
);

userlistSchema.pre("save", function (next) {
  if (!this.isModified("password")) {
    return next();
  }
  const password = this.password;
  const hasedpassword = bcrypt.hashSync(password, 10);
  this.password = hasedpassword;
  next();
});

userlistSchema.methods.vaificationToken = function () {
  const token = crypto.randomBytes(32).toString("hex");
  this.confirmationToken = token;

  let date = new Date();
  date.setDate(date.getDate() + 1);

  this.confirmationTokenExpirese = date;

  return token;
};

userlistSchema.methods.comparePassword = function (password, hash) {
  const isvalidPassword = bcrypt.compareSync(password, hash);

  return isvalidPassword;
};

userlistSchema.methods.passwordReset = function () {
  const token = crypto.randomBytes(4).toString("hex");
  this.passwordResetToken = token;
  let date = new Date();
  date.setDate(date.getDate() + 1);

  this.passwordResetExpirise = date;

  return token;
};

module.exports = mongoose.model("userlist", userlistSchema);
