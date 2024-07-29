const app = require('./app');
const mongoose = require('mongoose');
require('dotenv').config();

const dbURL =
'mongodb+srv://elhosary:nodejs@cluster0.vptdvxy.mongodb.net/';
  //'mongodb+srv://a7med3del1973:nodejs123@cluster0.gkjci2o.mongodb.net/TukRide';
 
mongoose
  .connect(dbURL, {
    useNewUrlParser: true,
  })
  .then(() => console.log('DB connection successful !'))
  .catch((err) => console.log('DB connection error : ', err));

const PORT = 8080;
app.listen(PORT, (req, res) => {
  console.log(`Server is running on port ${PORT} ..`);
});
