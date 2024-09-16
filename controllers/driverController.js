const fs = require('fs');
const crypto = require('crypto');
const Driver = require('../models/driverModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('./../utils/appError');
const sendEmail = require('./../utils/email');
const multer = require('multer');
const path = require('path');
const Ride = require('../models/rideModel');

const filterObj = (obj, ...allowedFields) => {
  const newObj = {};
  Object.keys(obj).forEach((el) => {
    if (allowedFields.includes(el)) newObj[el] = obj[el];
  });
  return newObj;
};



// Configure multer for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'public/img/drivers');
  },
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, `${file.fieldname}-${Date.now()}${ext}`);
  },
});

const upload = multer({ storage });

// Middleware to handle file uploads
exports.uploadDriverDocuments = upload.fields([
  { name: 'idCard', maxCount: 1 },
  { name: 'driverLicense', maxCount: 1 },
]);

exports.addDriverLicense = async (req, res) => {
  try {
    const { token, licenseNumber, expirationDate, dateOfBirth } = req.body;

    if (!token || !licenseNumber || !expirationDate || !dateOfBirth) {
      return res
        .status(400)
        .json({ message: 'Please provide all required fields.' });
    }

    const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

    const driver = await Driver.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!driver) {
      return res.status(400).json({ message: 'Invalid or expired token.' });
    }

    // Update driver fields
    driver.licenseNumber = licenseNumber;
    driver.expirationDate = expirationDate;
    driver.dateOfBirth = dateOfBirth;

    // Handle file uploads
    if (req.files) {
      if (req.files.idCard)
        driver.idCard = `img/drivers/${req.files.idCard[0].filename}`;
      if (req.files.driverLicense)
        driver.driverLicense = `img/drivers/${req.files.driverLicense[0].filename}`;
    }

    await driver.save({ validateBeforeSave: false });

    const verificationToken = driver.createPasswordResetToken();
    await driver.save({ validateBeforeSave: false });

    const emailOptions = {
      email: driver.email,
      subject: 'Verify Your Email',
      message: `Your verification code is: ${verificationToken}`,
    };

    await sendEmail(emailOptions);

    res.status(200).json({
      status: 'success',
      message:
        'License details added successfully. Please check your email for the verification code.',
    });
  } catch (error) {
    console.error('Error adding driver license:', error);
    res.status(500).json({ message: 'Error adding driver license.', error });
  }
};

exports.verifyEmail = async (req, res) => {
  try {
    const { driverId, code } = req.body;

    if (!driverId || !code) {
      return res
        .status(400)
        .json({ message: 'Please provide the verification code.' });
    }

    const hashedCode = crypto.createHash('sha256').update(code).digest('hex');

    const driver = await Driver.findOne({
      _id: driverId,
      passwordResetToken: hashedCode,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!driver) {
      return res
        .status(400)
        .json({ message: 'Invalid or expired verification code.' });
    }

    driver.isVerified = true;
    driver.passwordResetToken = undefined;
    driver.passwordResetExpires = undefined;

    await driver.save({ validateBeforeSave: false });

    res.status(200).json({
      status: 'success',
      message: 'Email verified successfully. You can now log in.',
    });
  } catch (error) {
    console.error('Error verifying email:', error);
    res.status(500).json({ message: 'Error verifying email.', error });
  }
};

exports.updateMe = catchAsync(async (req, res, next) => {
  // 1) Create error if driver POSTs password data
  if (req.body.password || req.body.passwordConfirm) {
    return next(
      new AppError(
        'This route is not for password updates. Please use /updateMyPassword.',
        400
      )
    );
  }

  // 3) Filtered out unwanted fildes names that are not allowed to be updated
  const filteredBody = filterObj(req.body, 'name', 'email');

  // 2) Update Driver document
  const updatedDriver = await Driver.findByIdAndUpdate(
    req.driver.id,
    filteredBody,
    {
      new: true,
      runValidators: true,
    }
  );
  res.status(200).json({
    status: 'success',
    data: {
      driver: updatedDriver,
    },
  });
});

exports.getDriverProfile = async (req, res) => {
  try {
    const driver = await Driver.findById(req.driver.id);
    if (!driver) {
      return res.status(404).json({ message: 'Driver not found.' });
    }

    res.status(200).json({ status: 'success', data: { driver } });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching profile.', error });
  }
};

exports.uploadDriverPhoto = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No photo uploaded.' });
    }

    const filePath = `uploads/drivers/${req.file.filename}`;
    fs.writeFileSync(filePath, req.file.buffer);

    res
      .status(200)
      .json({ status: 'success', message: 'Photo uploaded successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error uploading photo.', error });
  }
};

exports.resizeDriverPhoto = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: 'No photo to resize.' });
    }

    const resizedPhoto = await sharp(req.file.buffer)
      .resize(300, 300)
      .toBuffer();

    const filePath = `uploads/drivers/resized_${req.file.filename}`;
    fs.writeFileSync(filePath, resizedPhoto);

    res
      .status(200)
      .json({ status: 'success', message: 'Photo resized successfully.' });
  } catch (error) {
    res.status(500).json({ message: 'Error resizing photo.', error });
  }
};