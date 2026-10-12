const hasDangerousKey = (obj) => {
  if (!obj || typeof obj !== "object") return false;

  for (const key in obj) {
    if (
      key.startsWith("$") ||
      key.includes(".") ||
      key === "__proto__" ||
      key === "constructor" ||
      key === "prototype"
    ) {
      return true;
    }

    if (typeof obj[key] === "object" && hasDangerousKey(obj[key])) {
      return true;
    }
  }

  return false;
};

const sanitizeInput = (req, res, next) => {
  const sources = [req.body, req.query, req.params];

  for (const source of sources) {
    if (hasDangerousKey(source)) {
      return res.status(400).json({
        success: false,
        message: "Dangerous input detected",
      });
    }
  }

  next();
};

module.exports = sanitizeInput;