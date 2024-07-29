const express = require('express');
const morgan = require('morgan');
const userRoute = require('./routes/userRoutes');
const driverRoute = require('./routes/driverRoutes');
const AppError = require('./utils/appError');
const globalErrorHandler = require('./controllers/errorController');
const { default: mongoose } = require('mongoose');
const app = express();
app.use(morgan('dev'));
app.use(express.json());
require('dotenv').config();

// Middleware
app.use(express.json());
 //app.use('/', (req, res) => {
   //res.send('Hello World !');
 //});
// ROUTES
app.use('/user', userRoute);
app.use('/driver', driverRoute);

app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server!`, 404));
});

app.use(globalErrorHandler);

module.exports = app;