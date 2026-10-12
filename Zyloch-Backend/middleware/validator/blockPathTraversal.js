const pathTraversalPattern = /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\\)/i;

const blockPathTraversal = (fields = []) => {
  return (req, res, next) => {
    for (const field of fields) {
      const value =
        req.body?.[field] ||
        req.query?.[field] ||
        req.params?.[field];

      if (typeof value === "string" && pathTraversalPattern.test(value)) {
        return res.status(400).json({
          success: false,
          message: `Path traversal attempt detected in field: ${field}`,
        });
      }
    }

    next();
  };
};

module.exports = blockPathTraversal;