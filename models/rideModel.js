const mongoose = require('mongoose');

const rideSchema = new mongoose.Schema(
  {
    user: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: function() {
        return this.status !== 'available';
      },
    },
    driver: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'Driver',
      required: true,
    },
    startLocation: {
      type: {
        type: String,
        enum: ['Point'],
        required: true,
      },
      coordinates: {
        type: [Number],
        required: true,
      },
    },
    endLocation: {
      type: {
        type: String,
        enum: ['Point'],
        required: function() {
          return this.status !== 'available';
        },
      },
      coordinates: {
        type: [Number],
        required: function() {
          return this.status !== 'available';
        },
      },
    },
    fare: {
      type: Number,
      required: function() {
        return this.status === 'booked';
      },
    },
    status: {
      type: String,
      enum: ['pending', 'available', 'booked', 'upcoming', 'completed', 'cancelled'],
      default: 'pending',
    },
    startTime: {
      type: Date,
      required: function() {
        // Only required if the status is 'upcoming'
        return this.status === 'upcoming';
      },
    },
    endTime: {
      type: Date,
    },
    rating: {
      type: Number,
      min: 1,
      max: 5,
    },
    review: {
      type: String,
    },
  },
  { timestamps: true }
);

// Create a 2dsphere index for geospatial queries
rideSchema.index({ startLocation: '2dsphere' });
rideSchema.index({ endLocation: '2dsphere' });

const Ride = mongoose.model('Ride', rideSchema);
module.exports = Ride;
