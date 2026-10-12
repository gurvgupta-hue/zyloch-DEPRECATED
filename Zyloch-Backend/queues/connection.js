const Redis = require('ioredis');
const config = require('../config/redis');

if (!process.env.REDIS_URL) {
  console.error('REDIS_URL environment variable is not set!');
  process.exit(1);
}

const connection = new Redis(config.redis.url, {
  tls: config.redis.tls,
  maxRetriesPerRequest: config.redis.maxRetriesPerRequest,
});

connection.on('connect', () => {
  console.log('Redis connected for BullMQ');
});

connection.on('error', (err) => {
  console.error('Redis connection error:', err);
});

module.exports = connection;
