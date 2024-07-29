const fs = require('fs');
const Driver = require('../models/driverModel');
exports.registerDriver = (req, res) => {
  res
    .status(200)
    .json({ message: 'driver registerDiver not implemented yet.' });
};

exports.loginDriver = (req, res) => {
  res.status(200).json({ message: 'driver loginDriver not implemented yet.' });
};
exports.forgotPassword = (req, res) => {
  res
    .status(200)
    .json({ message: 'Driver forgotPassword not implemented yet.' });
};
exports.resetPassword = (req, res) => {
  res
    .status(200)
    .json({ message: 'Driver resetPassword not implemented yet.' });
};
exports.updatePassword = (req, res) => {
  res
    .status(200)
    .json({ message: 'Driver updatePassword not implemented yet.' });
};
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
exports.logoutDriver = (req, res) => {
  res.status(200).json({ message: 'User logout not implemented yet .' });
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
