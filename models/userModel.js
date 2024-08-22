const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const validator = require('validator');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  profile: {
    type: String,
    default: 'default profile.png',
  },
  useremail: {
    type: String,
    required: [true, 'Please provide your email '],
    unique: true,
    lowercase: true,
    validate: [validator.isEmail, 'Please provide a valid email'],
  },
  userphone: {
    type: String,
    required: [true, 'Please provide a number '],
    unique: true,
  },
  photo: String,
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: 8,
  },
  passwordConfirm: {
    type: String,
    validate: {
      // This only works on CREATE and SAVE!!!
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!',
    },
  },
  passwordChangedAt: Date,
  passwordResetExpires: Date,
  passwordResetCode: String,  
  passwordResetVerified: Boolean,
  active: {
    type: Boolean,
    default: true,
    select: false,
  },
});
// Encrypt password using bcrypt before saving the document
userSchema.pre('save', async function (next) {
  // Only run if the password field was modified or the document is new
  if (!this.isModified('password') || this.isNew) {
    if (this.passwordConfirm && this.passwordConfirm !== this.password) {
      return next(new Error('Passwords are not the same!'));
    }
    this.passwordConfirm = undefined; // Clear passwordConfirm field
  }
  
  // Hash the password
  this.password = await bcrypt.hash(this.password, 12);

  // Set passwordChangedAt
  if (!this.isNew) {
    this.passwordChangedAt = Date.now() - 1000;
  }

  next();
});

// Instance method to check if passwords match
userSchema.methods.correctPassword = async function (candidatePassword, userPassword) {
  return await bcrypt.compare(candidatePassword, userPassword);
};

// Check if the password was changed after a JWT was issued
userSchema.methods.changedPasswordAfter = function (JWTTimestamp) {
  if (this.passwordChangedAt) {
    const changedTimestamp = parseInt(this.passwordChangedAt.getTime() / 1000, 10);
    return JWTTimestamp < changedTimestamp;
  }
  // Return false if password has not been changed
  return false;
};




const User = mongoose.model('User', userSchema);

module.exports = User;