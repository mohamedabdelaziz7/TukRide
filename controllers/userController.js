const fs = require('fs');
const multer = require('multer');
const sharp = require('sharp');
const multerStorage = multer.memoryStorage();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/userModel');
const Ride = require('../models/rideModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require("../utils/appError");

exports.updateMe = catchAsync(async (req, res, next) => {
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updatePassword.',
        400
      )
    );
  }

  // Prepare data for updating
  const updateData = {
    username: req.body.username,
    useremail: req.body.useremail,
    userphone: req.body.userphone,
  };

  // Check if there's a new profile picture and update accordingly
  if (req.file) {
    updateData.profile = req.file.filename;
  }

  // Update user in the database
  const updatedUser = await User.findByIdAndUpdate(req.user._id, updateData, {
    new: true,
    runValidators: true,
  });

  res.status(200).json({
    status: 'success',
    data: {
      user: updatedUser,
    },
  });
});

exports.cancelRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findById(req.params.rideId);

  if (!ride) {
    return next(new AppError('No ride found with that ID', 404));
  }

  if (ride.user.toString() !== req.user._id.toString()) {
    return next(
      new AppError('You do not have permission to cancel this ride', 403)
    );
  }

  ride.status = 'cancelled';
  await ride.save();

  res.status(200).json({
    status: 'success',
    data: null,
  });
});

// give rate for the driver
exports.rateRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findById(req.params.rideId);

  if (!ride) {
    return next(new AppError('No ride found with that ID', 404));
  }

  if (ride.user.toString() !== req.user._id.toString()) {
    return next(new AppError('You do not have permission to rate this ride', 403));
  }

  
  ride.rating = req.body.rating;
  ride.review = req.body.review;
  await ride.save();

  res.status(200).json({
    status: 'success',
    data: {
      ride,
    },
  });
});
// show all availables rides
exports.availableRides = catchAsync(async (req, res, next) => {
  const rides = await Ride.find({ status: 'available' });

  res.status(200).json({
    status: 'success',
    results: rides.length,
    data: {
      rides,
    },
  });
});
// Book a ride
exports.bookRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findById(req.params.rideId);

  if (!ride) {
    return next(new AppError('No ride found with that ID', 404));
  }

  if (ride.status !== 'available') {
    return next(new AppError('This ride is no longer available', 400));
  }
  if (!ride.startTime || !ride.fare || !ride.startLocation || !ride.endLocation) {
    return next(new AppError('Missing required ride information', 400));
  }

  ride.status = 'booked';
  ride.user = req.user._id;
  await ride.save();

  res.status(200).json({
    status: 'success',
    data: {
      ride,
    },
  });
});

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
// Get user ride history
exports.rideHistory = catchAsync(async (req, res, next) => {
  const rides = await Ride.find({ user: req.user._id, status: 'completed' });

  res.status(200).json({
    status: 'success',
    results: rides.length,
    data: {
      rides,
    },
  });
});

exports.deleteMe = catchAsync(async (req, res, next) => {
  await User.findByIdAndDelete(req.user._id);

  res.status(204).json({
    status: 'success',
    data: null,
  });
});

exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  req.file.filename = `user-${req.user._id}-${Date.now()}.jpeg`;

  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ quality: 90 })
    .toFile(`public/img/users/${req.file.filename}`);

  next();
});

const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images.', 400), false);
  }
};

const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});

exports.uploadUserPhoto = upload.single('photo');
