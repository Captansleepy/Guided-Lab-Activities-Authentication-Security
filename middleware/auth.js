const jwt = require("jsonwebtoken");

function auth(req, res, next) {
  const header = req.headers.authorization;
  const match = typeof header === "string" ? /^Bearer\s+(\S+)$/i.exec(header) : null;

  if (!match) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    const payload = jwt.verify(match[1], process.env.JWT_SECRET);

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
