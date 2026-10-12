const cors = require("cors");

const corsMiddleware = cors({
  origin: function (origin, callback) {
    const allowedOrigin = process.env.FRONTEND_URL;

    if (!origin) return callback(null, true);

    if (origin === allowedOrigin) {
      return callback(null, true);
    }

    console.warn(`[CORS BLOCKED] ${origin}`);
    return callback(new Error("Not allowed by CORS"));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  allowedHeaders: [
    "Origin",
    "X-Requested-With",
    "Content-Type",
    "Accept",
    "Authorization",
  ],
});

module.exports = corsMiddleware;