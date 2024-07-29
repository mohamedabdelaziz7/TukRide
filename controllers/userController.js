const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const User = require("../models/userModel");
const AppError = require("../utils/appError");
const multer = require('multer');
const sharp = require('sharp');
// Function to sign JWT token
const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

// Function to create and send token
const createSendToken = (user, statusCode, res) => {
  const token = signToken(user._id);
  const cookieOptions = {
    expires: new Date(
      Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000
    ),
    httpOnly: true,
  };
  if (process.env.NODE_ENV === "production") cookieOptions.secure = true;

  res.cookie("jwt", token, cookieOptions);
  user.password = undefined;

  res.status(statusCode).json({
    status: "success",
    token,
    data: {
      user,
    },
  });
};

// Middleware to protect routes
exports.protect = async (req, res, next) => {
  try {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
      token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
      return res.status(401).json({ status: 'fail', message: 'You are not logged in!' });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const currentUser = await User.findById(decoded.id);
    if (!currentUser) {
      return res.status(401).json({ status: 'fail', message: 'The user no longer exists.' });
    }

    req.user = currentUser;
    next();
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
};

// Signup a new user
exports.signupUser = async (req, res) => {
  try {
    const newUser = await User.create({
      username: req.body.username,
      useremail: req.body.useremail,
      userphone: req.body.userphone,
      password: req.body.password,
    });

    createSendToken(newUser, 201, res);
  } catch (error) {
    if (error.code === 11000) {
      res.status(400).json({
        status: 'fail',
        message: 'Email already exists. Please use a different email.',
      });
    } else {
      res.status(400).json({
        status: 'fail',
        message: error.message,
      });
    }
  }
};

// Login an existing user
exports.loginUser = async (req, res, next) => {
  const { useremail, password } = req.body;

  if (!useremail || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const user = await User.findOne({ useremail }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  createSendToken(user, 200, res);
};

// Get user profile
exports.getUserProfile = async (req, res) => {
  try {
    const user = await User.findById(req.user._id);

    if (!user) {
      return res.status(404).json({ status: 'fail', message: 'User not found' });
    }

    res.status(200).json({
      status: 'success',
      data: {
        user
      }
    });
  } catch (err) {
    res.status(500).json({ status: 'error', message: err.message });
  }
};

// Update user profile
exports.updateMe = async (req, res) => {
  try {
    if (req.body.password || req.body.passwordConfirm) {
      return res.status(400).json({
        status: 'fail',
        message: 'This route is not for password updates. Please use /updateMyPassword.'
      });
    }

    const updatedUser = await User.findByIdAndUpdate(req.user._id, {
      username: req.body.username,
      useremail: req.body.useremail,
      userphone: req.body.userphone
    }, {
      new: true,
      runValidators: true
    });

    res.status(200).json({
      status: 'success',
      data: {
        user: updatedUser
      }
    });
  } catch (err) {
    res.status(500).json({
      status: 'error',
      message: err.message
    });
  }
};

// Delete user account
exports.deleteMe = async (req, res, next) => {
  await User.findByIdAndUpdate(req.user.id, { active: false });

  res.status(204).json({
    status: "success",
    data: null,
  });
};

// Update user password
exports.updatePassword = async (req, res, next) => {
  const user = await User.findById(req.user.id).select("+password");

  if (!(await user.correctPassword(req.body.currentPassword, user.password))) {
    return next(new AppError("Your current password is wrong", 401));
  }

  user.password = req.body.password;
  await user.save();

  createSendToken(user, 200, res);
};

// Reset user password
exports.resetPassword = async (req, res, next) => {
  const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  user.password = req.body.password;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  createSendToken(user, 200, res);
};

// Forgot password
exports.forgotPassword = async (req, res, next) => {
  const user = await User.findOne({ useremail: req.body.useremail });
  if (!user) {
    return next(new AppError("There is no user with email address", 404));
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${req.protocol}://${req.get("host")}/user/resetPassword/${resetToken}`;

  const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email`;

  try {
    res.status(200).json({
      status: "success",
      message: "Token sent to email",
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError("There was an error sending the email. Try again later", 500));
  }
};

// Logout user
exports.logout = (req, res) => {
  res.cookie("jwt", "loggedout", {
    expires: new Date(Date.now() + 10 * 1000),
    httpOnly: true,
  });
  res.status(200).json({ status: "success", message: 'User logged out successfully.' });
};

// Show available rides
exports.availableRides = (req, res) => {
  res.status(200).json({ message: 'User availableRides not implemented yet.' });
};

// Book a ride
exports.bookRide = (req, res) => {
  res.status(200).json({ message: 'User bookRide not implemented yet.' });
};

// Cancel a ride
exports.cancelRide = (req, res) => {
  res.status(200).json({ message: 'User cancelRide not implemented yet.' });
};

// Get user ride history
exports.rideHistory = (req, res) => {
  res.status(200).json({ message: 'User rideHistory not implemented yet.' });
};

// Rate a ride
exports.rateRide = (req, res) => {
  res.status(200).json({ message: 'User rateRide not implemented yet.' });
};

// Upload user photo
exports.uploadUserPhoto = (req, res) => {
  res.status(200).json({ message: 'User uploadUserPhoto not implemented yet.' });
};

// Resize user photo
exports.resizeUserPhoto = (req, res) => {
  res.status(200).json({ message: 'User resizeUserPhoto not implemented yet.' });
};

// Utility function to filter object fields
const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};
