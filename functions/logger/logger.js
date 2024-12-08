const winston = require('winston');
require('winston-mongodb');

// MongoDB connection URI
const dbURI = "mongodb+srv://eira_group:9WTclJhbG6Mr8bs2@logger.uofv7.mongodb.net/loggerDB?retryWrites=true&w=majority&tls=true"; // Replace with your MongoDB Atlas URI if applicable"

// Define MongoDB transport
const mongoTransport = new winston.transports.MongoDB({
  db: dbURI,
  collection: 'log_entries', // MongoDB collection to store logs
  level: 'debug',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.json() // Stores logs as JSON in the database
  ),
});


// Create logger
const logger = winston.createLogger({
  level: 'debug',
  transports: [
    mongoTransport,
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    }),
  ],
});

module.exports = logger;