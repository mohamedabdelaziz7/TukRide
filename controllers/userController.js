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
const mongoose = require('mongoose');
const ObjectId = mongoose.Types.ObjectId;
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
exports.getUserProfile = catchAsync(async (req, res, next) => {
  const user = await User.findById(req.user._id).select('name useremail userphone profile');

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

// Fetch all available rides sorted by proximity to the user
exports.availableRides = catchAsync(async (req, res, next) => {
  const { location, minFare, maxFare, startTime, maxDistance = 5 } = req.query;

  // Validate location
  if (!location) {
    return next(new AppError('Location is required', 400));
  }

  const [lng, lat] = location.split(',');
  const userLocation = { type: 'Point', coordinates: [parseFloat(lng), parseFloat(lat)] };

  // Initialize filter object
  let filter = { status: 'available' };

  // Validate and parse minFare
  if (minFare !== undefined) {
    const parsedMinFare = parseFloat(minFare);
    if (isNaN(parsedMinFare) || parsedMinFare < 0) {
      return next(new AppError('Invalid minFare value', 400));
    }
    filter.fare = { ...filter.fare, $gte: parsedMinFare };
  }

  // Validate and parse maxFare
  if (maxFare !== undefined) {
    const parsedMaxFare = parseFloat(maxFare);
    if (isNaN(parsedMaxFare) || parsedMaxFare < 0) {
      return next(new AppError('Invalid maxFare value', 400));
    }
    filter.fare = { ...filter.fare, $lte: parsedMaxFare };
  }

  // Ensure minFare is not greater than maxFare
  if (minFare && maxFare && parseFloat(minFare) > parseFloat(maxFare)) {
    return next(new AppError('minFare cannot be greater than maxFare', 400));
  }

  // Validate and parse startTime
  if (startTime) {
    const parsedStartTime = new Date(startTime);
    if (isNaN(parsedStartTime.getTime())) {
      return next(new AppError('Invalid startTime value', 400));
    }
    if (parsedStartTime < new Date()) {
      return next(new AppError('startTime cannot be in the past', 400));
    }
    filter.startTime = { $gte: parsedStartTime };
  }

  // Validate and parse maxDistance
  const parsedMaxDistance = parseFloat(maxDistance);
  if (isNaN(parsedMaxDistance) || parsedMaxDistance <= 0) {
    return next(new AppError('Invalid maxDistance value', 400));
  }

  // Proceed with the ride query
  const rides = await Ride.aggregate([
    {
      $geoNear: {
        near: userLocation,
        distanceField: 'distance',
        maxDistance: parsedMaxDistance * 1000, // Default 5 km radius, configurable
        spherical: true,
        key: 'startLocation',
      },
    },
    { $match: filter },
    { $sort: { distance: 1 } }, // Sort by distance, nearest first
  ]);

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
  const { rideId } = req.params;
  const { endLocation, fare } = req.body;

  // Check if the user already has an active ride
  const activeRide = await Ride.findOne({
    user: req.user._id,
    status: { $in: ['booked', 'upcoming'] },
  });

  if (activeRide) {
    return next(new AppError('You already have an active ride', 400));
  }

  const session = await mongoose.startSession();
  session.startTransaction();

  try {
    // Find the available ride by ID
    const ride = await Ride.findOne({ _id: rideId, status: 'available' }).session(session);

    if (!ride) {
      await session.abortTransaction();
      session.endSession();
      return next(new AppError('No ride found with that ID or the ride is not available', 404));
    }

    // Update ride details based on user input
    ride.status = 'booked';
    ride.user = req.user._id;
    ride.endLocation = endLocation;  // Set the end location
    ride.fare = fare;  // Set the fare offered by the user
    

    await ride.save({ session });

    await session.commitTransaction();
    session.endSession();

    res.status(200).json({
      status: 'success',
      data: {
        ride,
      },
    });
  } catch (err) {
    console.error('Error during booking:', err);
    await session.abortTransaction();
    session.endSession();
    return next(new AppError('Booking failed, please try again', 500));
  }
});

// Cancel a ride with time limit
exports.cancelRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findById(req.params.rideId);

  if (!ride) {
    return next(new AppError('No ride found with that ID', 404));
  }

  if (ride.user.toString() !== req.user._id.toString()) {
    return next(new AppError('You do not have permission to cancel this ride', 403));
  }

  const cancelTimeLimit = new Date(ride.startTime);
  cancelTimeLimit.setMinutes(cancelTimeLimit.getMinutes() - 10); // Allow cancellation until 10 mins before start

  if (new Date() > cancelTimeLimit) {
    return next(new AppError('Cannot cancel the ride within 10 minutes of start time', 400));
  }

  ride.status = 'cancelled';
  await ride.save();

  res.status(200).json({
    status: 'success',
    data: null,
  });
});

// Rate the ride
exports.rateRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findById(req.params.rideId);

  if (!ride) {
    return next(new AppError('No ride found with that ID', 404));
  }

  if (ride.user.toString() !== req.user._id.toString()) {
    return next(new AppError('You do not have permission to rate this ride', 403));
  }

  if (ride.status !== 'completed') {
    return next(new AppError('You can only rate a completed ride', 400));
  }

  const rating = parseFloat(req.body.rating);
  if (rating < 1 || rating > 5) {
    return next(new AppError('Rating must be between 1 and 5', 400));
  }

  ride.rating = rating;
  ride.review = req.body.review;
  await ride.save();

  res.status(200).json({
    status: 'success',
    data: {
      ride,
    },
  });
});

// Get user completed rides
exports.completedRides = catchAsync(async (req, res, next) => {
  const completedRides = await Ride.find({
    user: req.user._id,
    status: 'completed'
  }).select('endLocation startTime').limit(10).skip(req.query.page * 10 || 0);

  res.status(200).json({
    status: 'success',
    results: completedRides.length,
    data: {
      rides: completedRides,
    },
  });
});

// Get user upcoming rides
exports.upcomingRides = catchAsync(async (req, res, next) => {
  const rides = await Ride.find({
    user: req.user._id,
    status: { $in: ['booked', 'upcoming'] },
  });

  res.status(200).json({
    status: 'success',
    results: rides.length,
    data: {
      rides,
    },
  });
});

// Start the ride
exports.startRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findOneAndUpdate(
    {
      _id: req.params.rideId,
      status: 'booked',
    },
    {
      status: 'upcoming',
      startTime: new Date(), // Automatically record the start time
    },
    { new: true }
  );

  if (!ride) {
    return next(new AppError('No ride found with that ID or ride is not in a state that can be started', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      ride,
    },
  });
});

// End the ride
exports.endRide = catchAsync(async (req, res, next) => {
  const ride = await Ride.findOneAndUpdate(
    {
      _id: req.params.rideId,
      status: 'upcoming',
    },
    {
      status: 'completed',
      endTime: new Date(), // Automatically record the end time
    },
    { new: true }
  );

  if (!ride) {
    return next(new AppError('No ride found with that ID or ride is not in a state that can be ended', 404));
  }

  res.status(200).json({
    status: 'success',
    data: {
      ride,
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

//share location
exports.updateLocation = catchAsync(async (req, res, next) => {
  const { latitude, longitude } = req.body;

  if (!latitude || !longitude) {
      return next(new AppError('Please provide both latitude and longitude.', 400));
  }

  const updatedUser = await User.findByIdAndUpdate(
      req.user.id,
      { location: { type: 'Point', coordinates: [longitude, latitude] } },
      { new: true, runValidators: true }
  );

  res.status(200).json({
      status: 'success',
      data: {
          user: updatedUser,
      },
  });
});