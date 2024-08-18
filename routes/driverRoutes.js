const express = require('express');
const driverController = require('../controllers/driverController');
const router = express.Router();
const authController = require('../controllers/authController');
const {
  uploadDriverPhoto,
  resizeDriverPhoto,
} = require('../middlewares/fileUploead');

// Password management routes
router.post('/forgotPassword', authController.forgotPasswordDriver);
router.patch('/resetPassword/:token', authController.resetPasswordDriver);
router.patch(
  '/updateMyPassword',
  authController.protect,
  authController.updatePasswordDriver
);

router.post('/signup', authController.signupDriver);
router.post('/login', authController.loginDriver);
router.get('/logout', authController.logout);

// User profile routes
router.patch(
  '/updateMe',
  authController.protect,
  uploadDriverPhoto,
  resizeDriverPhoto,
  driverController.updateDriverProfile
);

// router.delete('/deleteMe', driverController.deleteMe);
router.get(
  '/profile',
  authController.protect,
  driverController.getDriverProfile
);

// Ride management routes
router.get('/availableRides', driverController.availableRides);
router.get('/rideHistory', driverController.rideHistory);

module.exports = router;
