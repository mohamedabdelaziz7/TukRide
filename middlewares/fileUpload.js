const multer = require('multer');
const sharp = require('sharp');
const fs = require('fs');
const path = require('path');
const AppError = require('../utils/appError');
const catchAsync = require('../utils/catchAsync');

// Configure multer storage

const multerStorage = multer.memoryStorage();

// Filter to accept only images
const multerFilter = (req, file, cb) => {
  if (file.mimetype.startsWith('image')) {
    cb(null, true);
  } else {
    cb(new AppError('Not an image! Please upload only images.', 400), false);
  }
};

// Initialize multer with storage and filter
const upload = multer({
  storage: multerStorage,
  fileFilter: multerFilter,
});

// Middleware to upload single photo
exports.uploadUserPhoto = upload.single('photo');

// Middleware to resize and save the photo
exports.resizeUserPhoto = catchAsync(async (req, res, next) => {
  if (!req.file) return next();

  // Define file path and filename
  const filePath = path.join(__dirname, '../public/img/users');
  const fileName = `user-${req.user.id}-${Date.now()}.jpeg`;

  // Ensure the directory exists
  if (!fs.existsSync(filePath)) {
    fs.mkdirSync(filePath, { recursive: true });
  }

  // Resize and save the image
  await sharp(req.file.buffer)
    .resize(500, 500)
    .toFormat('jpeg')
    .jpeg({ quality: 90 })
    .toFile(path.join(filePath, fileName));

  // Save the filename to the request object for further use
  req.file.filename = fileName;

  next();
});
