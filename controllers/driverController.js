const fs = require('fs');
const Driver = require('../models/driverModel');

// show all availables rides
exports.availableRides = (req, res) => {
  res
    .status(200)
    .json({ message: 'driver availableRides not implemented yet.' });
};
// Book a ride

exports.updateDriverProfile = (req, res) => {
  res
    .status(200)
    .json({ message: 'driver updateUserProfile not implemented yet.' });
};

exports.getDriverProfile = (req, res) => {
  res
    .status(200)
    .json({ message: 'driver getDriverProfile not implemented yet.' });
};

// Get user ride history
exports.rideHistory = (req, res) => {
  res.status(200).json({ message: 'driver rideHistory not implemented yet.' });
};

exports.uploadDriverPhoto = (req, res) => {
  res
    .status(200)
    .json({ message: 'User uploadUserPhoto not implemented yet.' });
};
exports.resizeDriverPhoto = (req, res) => {
  res
    .status(200)
    .json({ message: 'User resizeUserPhoto not implemented yet.' });
};
