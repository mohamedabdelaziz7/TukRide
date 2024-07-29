const express = require('express');

const driverController = require('../controllers/driverController');

const router = express.Router();

// Password management routes
router.post('/forgotPassword', driverController.forgotPassword);
router.patch('/resetPassword/:token', driverController.resetPassword);
router.patch('/updateMyPassword', driverController.updatePassword);

// Authentication routes
router.post('/register', driverController.registerDriver);
router.post('/login', driverController.loginDriver);
router.get('/logout', driverController.logoutDriver);
//
// User profile routes
router.patch(
  '/updateMe',
  driverController.uploadDriverPhoto,
  driverController.resizeDriverPhoto,
  driverController.updateDriverProfile
);
// router.delete('/deleteMe', driverController.deleteMe);
router.get('/profile', driverController.getDriverProfile);

// Ride management routes
router.get('/availableRides', driverController.availableRides);
router.get('/rideHistory', driverController.rideHistory);
module.exports = router;
