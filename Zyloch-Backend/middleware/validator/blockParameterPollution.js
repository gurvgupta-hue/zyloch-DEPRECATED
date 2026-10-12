const blockParameterPollution = (req, res, next) => {
  for (const key in req.query) {
    if (Array.isArray(req.query[key])) {
      return res.status(400).json({
        success: false,
        message: `Parameter pollution detected for: ${key}`,
      });
    }
  }

  next();
};

module.exports = blockParameterPollution;