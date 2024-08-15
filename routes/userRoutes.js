const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');
const { uploadUserPhoto, resizeUserPhoto } = require('../middlewares/fileUpload');

const router = express.Router();

router.post('/signup', authController.signupUser);
router.post('/login', authController.loginUser);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);

router.get('/logout', authController.protect, authController.logout);

router.patch('/updatePassword', authController.protect, authController.updatePassword);


//
router.use(authController.protect);


router.get('/profile', userController.getUserProfile);
router.patch('/updateMe', uploadUserPhoto, resizeUserPhoto, userController.updateMe);
router.delete('/deleteMe', userController.deleteMe);


router.get('/availableRides', userController.availableRides);
router.post('/bookRide', userController.bookRide);
router.post('/cancelRide', userController.cancelRide);
router.get('/rideHistory', userController.rideHistory);
router.post('/rateRide', userController.rateRide);

module.exports = router;


