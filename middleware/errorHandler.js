function errorHandler(error, req, res, next) {
  if (res.headersSent) {
    return next(error);
  }

  if (error.name === "ValidationError") {
    return res.status(400).json({ error: "Invalid data" });
  }

  if (error.code === 11000) {
    return res.status(400).json({ error: "Email already registered" });
  }

  if (error.type === "entity.too.large") {
    return res.status(413).json({ error: "Request body too large" });
  }

  if (error instanceof SyntaxError && error.status === 400 && "body" in error) {
    return res.status(400).json({ error: "Invalid JSON body" });
  }

  console.error(error);
  return res.status(500).json({ error: "Server error" });
}

module.exports = errorHandler;
