const mongoose = require('mongoose');
const driverSchema = new mongoose.Schema({
  profile: {
    type: String,
    default: 'default profile.png',
  },
  drivername: {
    type: String,
    required: true,
  },
  driveremail: {
    type: String,
    required: true,
    unique: true,
  },
  driverphone: {
    type: String,
    required: true,
    unique: true,
  },
  status: {
    type: Boolean,
    default: false,
  },
});

const Driver = mongoose.model('Driver', driverSchema);

module.exports = Driver;
