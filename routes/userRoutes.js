const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');

const router = express.Router();

// Password management routes
router.post('/forgotPassword', authController.forgotPasswordUser);
router.post('/verifyCode', authController.verifyPasswordResetCode);
router.patch('/resetPassword', authController.resetPasswordUser);

router.patch(
  '/updateMyPassword',
  authController.protect,
  authController.updatePasswordUser
);

// Authentication routes
router.post('/signup', authController.signupUser);
router.post('/login', authController.loginUser);
router.get('/logout', authController.protect, authController.logout);

// User profile routes
router.use(authController.protect);
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
//
router.post('/verifyEmail', authController.verifyEmailUser);
router.post('/resendVerificationCode', authController.resendVerificationCode);


module.exports = router;
