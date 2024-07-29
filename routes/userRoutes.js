const express = require('express');
const userController = require('../controllers/userController');

const router = express.Router();

// Password management routes
router.post('/forgotPassword', userController.forgotPassword);
router.patch('/resetPassword/:token', userController.resetPassword);
router.patch('/updateMyPassword', userController.updatePassword);

// Authentication routes
router.post('/signup', userController.signupUser);
router.post('/login', userController.loginUser);
router.get('/logout', userController.logout);

// Middleware to protect routes
router.use(userController.protect);

// User profile routes
router.patch(
  '/updateMe',
  userController.uploadUserPhoto,
  userController.resizeUserPhoto,
  userController.updateMe
);
router.delete('/deleteMe', userController.deleteMe);
router.get('/profile', userController.getUserProfile);

// Ride management routes
router.post('/bookRide', userController.bookRide);
router.delete('/cancelRide/:rideId', userController.cancelRide);
router.get('/availableRides', userController.availableRides);
router.get('/rideHistory', userController.rideHistory);

// Ride rating route
router.post('/rateRide/:rideId', userController.rateRide);

module.exports = router;

