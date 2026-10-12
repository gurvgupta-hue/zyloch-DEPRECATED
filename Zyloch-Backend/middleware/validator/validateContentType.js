const validateContentType = (allowedTypes = ["application/json"]) => {
  return (req, res, next) => {
    const method = req.method.toUpperCase();
    const methodsToCheck = ["POST", "PUT", "PATCH"];

    if (!methodsToCheck.includes(method)) {
      return next();
    }

    const contentType = req.headers["content-type"] || "";
    const matched = allowedTypes.some((type) =>
      contentType.toLowerCase().startsWith(type.toLowerCase())
    );

    if (!matched) {
      return res.status(415).json({
        success: false,
        message: "Unsupported Content-Type",
      });
    }

    next();
  };
};

module.exports = validateContentType;