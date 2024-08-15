const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema({
  profile: {
    type: String,
    default: 'default profile.png',
  },
  username: {
    type: String,
    required: [true, 'Please provide a username'],
  },
  useremail: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,  
  },
  userphone: {
    type: String,
    required: true,
    unique: true,
  },
  photo: {
    type: String,
    default: 'default.jpg',
  },
  password: {
    type: String,
    required: [true, 'Please provide a password'],
    minlength: [8, 'Password must be at least 8 characters long'],
    select: false,  // Ensures the password is not returned in queries
  },
  passwordConfirm: {
    type: String,
    required: [true, 'Please confirm your password'],
    validate: {
      // Custom validator to check that passwords match
      validator: function (el) {
        return el === this.password;
      },
      message: 'Passwords are not the same!',
    },
  },
  passwordChangedAt: Date,
  passwordResetToken: String,
  passwordResetExpires: Date,
  active: {
    type: Boolean,
    default: true,
    select: false,
  }
});

// Encrypt password using bcrypt before saving the document
userSchema.pre('save', async function (next) {
  // Only run if the password field was modified
  if (!this.isModified('password')) return next();

  // Hash the password with a cost of 12
  this.password = await bcrypt.hash(this.password, 12);

  // Set `passwordChangedAt` to the current time when password changes
  if (!this.isNew) {
    this.passwordChangedAt = Date.now() - 1000;  // Ensure token is created after password change
  }

  // Clear `passwordConfirm` field as it is not needed in the DB
  this.passwordConfirm = undefined;
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

// Generate and hash password reset token
userSchema.methods.createPasswordResetToken = function () {
  // Create reset token
  const resetToken = crypto.randomBytes(32).toString('hex');

  // Hash the token and set it on the user schema
  this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');

  // Set expiration time for token (10 minutes from now)
  this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

  // Return the raw reset token (to be sent to the user)
  return resetToken;
};

const User = mongoose.model('User', userSchema);

module.exports = User;

