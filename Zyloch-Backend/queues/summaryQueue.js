const { Queue } = require('bullmq');
const connection = require('./connection');
const config = require('../config/redis');

const summaryQueue = new Queue('installation-summary', {
  connection,
  defaultJobOptions: config.defaultJobOptions,
});

summaryQueue.on('error', (error) => {
  console.error('? Queue error:', error);
});

module.exports = summaryQueue;
