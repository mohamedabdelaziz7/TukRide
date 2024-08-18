const express = require('express');
const morgan = require('morgan');
const userRoute = require('./routes/userRoutes');
const driverRoute = require('./routes/driverRoutes');
const AppError = require('./utils/appError');
const glopalErrorHandler = require('./controllers/errorController');
const { default: mongoose } = require('mongoose');
const app = express();
app.use(morgan('dev'));
app.use(express.json());
const cookieParser = require('cookie-parser');

// Use cookie-parser middleware
app.use(cookieParser());
// app.use('/', (req, res) => {
//   res.send('Hello World !');
// });
// ROUTES
app.use('/user', userRoute);
app.use('/driver', driverRoute);
app.all('*', (req, res, next) => {
  next(new AppError(`Can't find ${req.originalUrl} on this server !`));
});

app.use(glopalErrorHandler);

module.exports = app;
