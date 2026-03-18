// ================== ATTACH USER ==================

function attachUser(req, res, next) {
  // Always expose user to EJS
  res.locals.user = req.session && req.session.user ? req.session.user : null;
  next();
}

// ================== REQUIRE AUTH ==================

function requireAuth(req, res, next) {
  const user = req.session && req.session.user;

  if (!user) {
    if (req.session) {
      req.session.flash = {
        type: "error",
        message: "Please login to continue",
      };
    }
    return res.redirect("/login");
  }

  next();
}

// ================== REQUIRE ADMIN ==================

function requireAdmin(req, res, next) {
  const user = req.session && req.session.user;

  if (!user) {
    return res.redirect("/login");
  }

  if (user.role !== "admin") {
    if (req.session) {
      req.session.flash = {
        type: "error",
        message: "Admin access required",
      };
    }
    return res.redirect("/dashboard");
  }

  next();
}

// ================== REQUIRE RED TEAM ==================

function requireRedTeam(req, res, next) {
  const user = req.session && req.session.user;

  if (!user) {
    return res.redirect("/login");
  }

  if (!["red", "admin"].includes(user.role)) {
    if (req.session) {
      req.session.flash = {
        type: "error",
        message: "Access denied (Red Team only)",
      };
    }
    return res.redirect("/dashboard");
  }

  next();
}

// ================== REQUIRE BLUE TEAM ==================

function requireBlueTeam(req, res, next) {
  const user = req.session && req.session.user;

  if (!user) {
    return res.redirect("/login");
  }

  if (!["blue", "admin"].includes(user.role)) {
    if (req.session) {
      req.session.flash = {
        type: "error",
        message: "Access denied (Blue Team only)",
      };
    }
    return res.redirect("/dashboard");
  }

  next();
}

// ================== EXPORT ==================

module.exports = {
  attachUser,
  requireAuth,
  requireAdmin,
  requireRedTeam,
  requireBlueTeam,
};
