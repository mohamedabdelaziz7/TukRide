const User = require("../models/userModel");
const AppError = require("../utils/appError");
const catchAsync = require("../utils/catchAsync");


exports.getUserProfile = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id);

  if (!user) {
    return next(new AppError('User not found', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      user
    }
  });
});

exports.updateMe = catchAsync(async (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm) {
    return next(new AppError('This route is not for password updates. Please use /updatePassword.', 400));
  }

  // Prepare data for updating
  const updateData = {
    username: req.body.username,
    useremail: req.body.useremail,
    userphone: req.body.userphone
  };

  // Check if there's a new profile picture and update accordingly
  if (req.file) {
    updateData.profile = req.file.filename;
  }

  // Update user in the database
  const updatedUser = await User.findByIdAndUpdate(req.user._id, updateData, {
    new: true,
    runValidators: true
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser
    }
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndDelete(req.user.id);

  res.status(204).json({
    status: "success",
    data: null,
  });
});




exports.availableRides = (req, res) => {
  res.status(200).json({ message: 'User availableRides not implemented yet.' });
};

exports.bookRide = (req, res) => {
  res.status(200).json({ message: 'User bookRide not implemented yet.' });
};

exports.cancelRide = (req, res) => {
  res.status(200).json({ message: 'User cancelRide not implemented yet.' });
};

exports.rideHistory = (req, res) => {
  res.status(200).json({ message: 'User rideHistory not implemented yet.' });
};

exports.rateRide = (req, res) => {
  res.status(200).json({ message: 'User rateRide not implemented yet.' });
};
