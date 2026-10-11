const jwt = require("jsonwebtoken");

function auth(req, res, next) {
  const header = req.headers.authorization;
  const [scheme, token] = typeof header === "string" ? header.split(/\s+/) : [];

  if (scheme !== "Bearer" || !token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const payload = jwt.verify(token, process.env.JWT_SECRET);

    if (typeof payload === "string" || !payload.id || !payload.role) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.user = { id: payload.id, role: payload.role };
    return next();
  } catch {
    return res.status(401).json({ error: "Invalid token" });
  }
}

module.exports = auth;
