const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');

const router = express.Router();

// Password management routes
router.post('/forgotPassword', authController.forgotPasswordUser);
router.post('/verifyCode', authController.verifyPasswordResetCode);
router.patch('/resetPassword', authController.resetPasswordUser);

// Authentication routes
router.post('/signup', authController.signupUser);
router.post('/login', authController.loginUser);

// Email verification routes (No JWT required)
//router.post('/verifyEmail', authController.verifyEmailUser);
//router.post('/resendVerificationCode', authController.resendVerificationCode);

// Protected routes (JWT required)
router.use(authController.protect); // Protect all routes below this line

router.patch('/updateMyPassword', authController.updatePasswordUser);
router.get('/logout', authController.logout);

// User profile routes
router.get('/profile', userController.getUserProfile);
router.patch(
  '/updateMe',
  userController.uploadUserPhoto,
  userController.resizeUserPhoto,
  userController.updateMe
);
router.delete('/deleteMe', userController.deleteMe);

// Endpoint to update user location
router.patch('/updateLocation', userController.updateLocation);

// Ride management routes
router.get('/availableRides', userController.availableRides);
router.post('/bookRide/:rideId', userController.bookRide);
router.delete('/cancelRide/:rideId', userController.cancelRide);

// New routes for starting and completing rides
router.patch('/startRide/:rideId', userController.startRide);
router.patch('/endRide/:rideId', userController.endRide);

// Upcoming and completed rides routes
router.get('/upcomingRides', userController.upcomingRides);
router.get('/completedRides', userController.completedRides);

// Ride rating route
router.post('/rateRide/:rideId', userController.rateRide);

module.exports = router;
