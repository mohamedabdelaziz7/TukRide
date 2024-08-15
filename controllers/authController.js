const crypto = require("crypto");
const { promisify } = require("util");
const jwt = require("jsonwebtoken");
const User = require("../models/userModel");
const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");
const sendEmail = require("../utils/email");

const signToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES_IN,
  });
};

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

// User signup
exports.signupUser = catchAsync(async (req, res, next) => {
  const newUser = await User.create({
    username: req.body.username,
    useremail: req.body.useremail,
    userphone: req.body.userphone,
    password: req.body.password,
    passwordConfirm: req.body.passwordConfirm,
  });

  createSendToken(newUser, 201, res);
});

// User login
exports.loginUser = catchAsync(async (req, res, next) => {
  const { useremail, password } = req.body;

  if (!useremail || !password) {
    return next(new AppError("Please provide email and password", 400));
  }

  const user = await User.findOne({ useremail }).select("+password");

  if (!user || !(await user.correctPassword(password, user.password))) {
    return next(new AppError("Incorrect email or password", 401));
  }

  createSendToken(user, 200, res);
});

// User logout
const jwtBlacklist = new Set(); // Can be a more persistent storage like Redis for scaling

exports.logout = (req, res) => {
  // Check if the cookie exists
  const token = req.cookies.jwt;

  // If there's no JWT cookie, the user is already logged out
  if (!token) {
    return res.status(400).json({
      status: 'error',
      message: 'You are already logged out!',
    });
  }

  // Blacklist the token (if using blacklist approach)
  jwtBlacklist.add(token);

  // Clear the JWT cookie by setting it to 'loggedout'
  res.cookie('jwt', 'loggedout', {
    expires: new Date(Date.now() + 10 * 1000), // Expires in 10 seconds
    httpOnly: true,
  });

  res.status(200).json({
    status: 'success',
    message: 'You are now logged out!',
  });
};


// Protect routes
exports.protect = catchAsync(async (req, res, next) => {
  let token;
  if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
    token = req.headers.authorization.split(' ')[1];
  } else if (req.cookies.jwt) {
    token = req.cookies.jwt;
  }

  // Check if token exists
  if (!token || token === 'loggedout') {
    return next(new AppError('You are logged out! Please log in again.', 401));
  }

  // Check if token is blacklisted
  if (jwtBlacklist.has(token)) {
    return next(new AppError('You are logged out! Please log in again.', 401));
  }

  // Verify the token
  const decoded = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

  const currentUser = await User.findById(decoded.id);
  if (!currentUser) {
    return next(new AppError('The user no longer exists.', 401));
  }

  if (currentUser.changedPasswordAfter(decoded.iat)) {
    return next(new AppError('User recently changed password! Please log in again.', 401));
  }

  req.user = currentUser;
  next();
});



// Forgot password
exports.forgotPassword = catchAsync(async (req, res, next) => {
  const user = await User.findOne({ useremail: req.body.useremail });
  if (!user) {
    return next(new AppError("There is no user with that email address", 404));
  }

  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });

  const resetURL = `${req.protocol}://${req.get("host")}/user/resetPassword/${resetToken}`;
  const message = `Forgot your password? Submit a PATCH request with your new password to: ${resetURL}.\nIf you didn't forget your password, please ignore this email.`;

  try {
    await sendEmail({
      email: user.useremail,
      subject: 'Your password reset token (valid for 10 minutes)',
      message,
    });

    res.status(200).json({
      status: 'success',
      message: 'Token sent to email!',
    });
  } catch (err) {
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save({ validateBeforeSave: false });

    return next(new AppError('There was an error sending the email. Try again later!', 500));
  }
});

// Reset password
exports.resetPassword = catchAsync(async (req, res, next) => {
  const hashedToken = crypto.createHash("sha256").update(req.params.token).digest("hex");

  const user = await User.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() },
  });

  if (!user) {
    return next(new AppError("Token is invalid or has expired", 400));
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm;
  user.passwordResetToken = undefined;
  user.passwordResetExpires = undefined;
  await user.save();

  createSendToken(user, 200, res);
});

// Update password
exports.updatePassword = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user.id).select("+password");

  if (!(await user.correctPassword(req.body.passwordCurrent, user.password))) {
    return next(new AppError("Your current password is wrong", 401));
  }

  user.password = req.body.password;
  user.passwordConfirm = req.body.passwordConfirm; 
  await user.save();

  createSendToken(user, 200, res);
});
