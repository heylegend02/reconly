require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const helmet = require("helmet");
const bcrypt = require("bcryptjs");
const multer = require("multer");
const validator = require("validator");

const {
  initDb,
  createUser,
  updateUserById,
  findUserByUsernameOrEmail,
  findUserById,
  listUsers,
  deleteUserById,
  logActivity,
  fetchActivityLogs,
  fetchActivityLogsByUserId,
  deleteActivityLogById,
  clearActivityLogs,
  countDashboardStats,
} = require("./db");

const {
  redModules,
  blueModules,
  getRedModuleByKey,
  getBlueModuleByKey,
} = require("./config/functionCatalog");

const {
  attachUser,
  requireAuth,
  requireAdmin,
  requireRedTeam,
  requireBlueTeam,
} = require("./middleware/auth");

const {
  executeRedModule,
  executeBlueModule,
} = require("./services/moduleExecutionService");
const { formatResultHtml } = require("./services/resultFormatter");

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 },
});
const sessionCookieName = "reconly.sid";

app.set("trust proxy", 1);
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    name: sessionCookieName,
    secret: process.env.SESSION_SECRET || "secret",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      maxAge: 8 * 60 * 60 * 1000,
    },
  })
);

app.use((req, res, next) => {
  res.locals.flash = req.session?.flash || null;
  req.session.flash = null;
  next();
});

app.use(attachUser);

function setFlash(req, type, message) {
  if (!req.session) {
    return;
  }

  req.session.flash = { type, message };
}

function loginFlashFromReason(reason) {
  if (reason === "inactive") {
    return {
      type: "error",
      message: "You were signed out after 5 minutes of inactivity.",
    };
  }

  if (reason === "logout") {
    return {
      type: "success",
      message: "You have been logged out.",
    };
  }

  return null;
}

function sanitizeText(value) {
  return String(value || "").trim();
}

function normalizeEmail(value) {
  return sanitizeText(value).toLowerCase();
}

function parsePositiveInt(value, fallback) {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function getActiveModule(modules, moduleKey, fallbackGetter) {
  if (moduleKey) {
    const requestedModule = fallbackGetter(moduleKey);
    if (requestedModule) {
      return requestedModule;
    }
  }

  return modules[0];
}

function buildActiveSection(prefix, activeModule) {
  return `${prefix}-${activeModule.key}`;
}

function validateRegistrationInput({ username, email, password, confirmPassword, team }) {
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
    throw new Error("Username must be 3-24 characters and use only letters, numbers, or underscore.");
  }

  if (!validator.isEmail(email)) {
    throw new Error("Please enter a valid email address.");
  }

  if (password.length < 8) {
    throw new Error("Password must be at least 8 characters long.");
  }

  if (password !== confirmPassword) {
    throw new Error("Passwords do not match.");
  }

  if (!["red", "blue"].includes(team)) {
    throw new Error("Choose either Red Team or Blue Team access.");
  }
}

function validateAdminUserUpdate({ username, email, role, newPassword }) {
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) {
    throw new Error("Username must be 3-24 characters and use only letters, numbers, or underscore.");
  }

  if (!validator.isEmail(email)) {
    throw new Error("Please enter a valid email address.");
  }

  if (!["red", "blue", "admin"].includes(role)) {
    throw new Error("Invalid role selected.");
  }

  if (newPassword && newPassword.length < 8) {
    throw new Error("New password must be at least 8 characters long.");
  }
}

function renderRegister(res, options = {}) {
  const { flash = null } = options;
  return res.render("register", {
    title: "Register",
    pageId: "register",
    flash,
  });
}

function renderLogin(req, res, options = {}) {
  const { flash = null } = options;
  return res.render("login", {
    title: "Login",
    pageId: "login",
    flash: flash || res.locals.flash || loginFlashFromReason(req.query.reason),
  });
}

function renderRedTeam(req, res, options = {}) {
  const {
    moduleKey = req.body?.moduleKey || req.query?.module,
    result = null,
    flash = null,
    statusCode = 200,
  } = options;

  const activeModule = getActiveModule(redModules, moduleKey, getRedModuleByKey);

  return res.status(statusCode).render("red-team", {
    title: "Red Team",
    pageId: "red-team",
    user: req.session.user,
    modules: redModules,
    activeModule,
    activeSection: buildActiveSection("rt", activeModule),
    result,
    flash,
    formatResultHtml,
  });
}

function renderBlueTeam(req, res, options = {}) {
  const {
    moduleKey = req.body?.moduleKey || req.query?.module,
    result = null,
    flash = null,
    statusCode = 200,
  } = options;

  const activeModule = getActiveModule(blueModules, moduleKey, getBlueModuleByKey);

  return res.status(statusCode).render("blue-team", {
    title: "Blue Team",
    pageId: "blue-team",
    user: req.session.user,
    modules: blueModules,
    activeModule,
    activeSection: buildActiveSection("bt", activeModule),
    result,
    flash,
    formatResultHtml,
  });
}

function regenerateSession(req) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

function destroySession(req) {
  return new Promise((resolve, reject) => {
    if (!req.session) {
      resolve();
      return;
    }

    req.session.destroy((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

app.get("/healthz", (_req, res) => {
  res.json({ status: "ok" });
});

app.get("/", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }

  return res.render("index", {
    title: "OSINT Command Center",
    pageId: "landing",
  });
});

app.get("/register", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }

  return renderRegister(res);
});

app.post("/register", async (req, res) => {
  const username = sanitizeText(req.body.username);
  const email = normalizeEmail(req.body.email);
  const password = String(req.body.password || "");
  const confirmPassword = String(req.body.confirmPassword || "");
  const team = sanitizeText(req.body.team);

  try {
    validateRegistrationInput({ username, email, password, confirmPassword, team });

    const [usernameMatch, emailMatch] = await Promise.all([
      findUserByUsernameOrEmail(username),
      findUserByUsernameOrEmail(email),
    ]);

    if (usernameMatch) {
      throw new Error("That username is already in use.");
    }

    if (emailMatch) {
      throw new Error("That email is already in use.");
    }

    const created = await createUser({ username, email, password, role: team });
    await logActivity({
      userId: created.id,
      action: "register",
      target: username,
      status: "success",
      details: `New ${team} account created.`,
    });

    return res.redirect("/login?reason=registered");
  } catch (error) {
    return renderRegister(res, {
      flash: {
        type: "error",
        message: error.message || "Registration failed.",
      },
    });
  }
});

app.get("/login", (req, res) => {
  if (req.session.user) {
    return res.redirect("/dashboard");
  }

  const flash =
    req.query.reason === "registered"
      ? { type: "success", message: "Account created successfully. You can sign in now." }
      : null;

  return renderLogin(req, res, { flash });
});

app.post("/login", async (req, res) => {
  const identifier = sanitizeText(req.body.identifier);
  const password = String(req.body.password || "");

  try {
    if (!identifier || !password) {
      throw new Error("Username/email and password are required.");
    }

    const user = await findUserByUsernameOrEmail(identifier);
    if (!user || !user.password_hash) {
      throw new Error("Invalid username/email or password.");
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      throw new Error("Invalid username/email or password.");
    }

    await regenerateSession(req);
    req.session.user = {
      id: user.id,
      username: user.username,
      email: user.email,
      role: user.role,
    };

    await logActivity({
      userId: user.id,
      action: "login",
      target: user.username,
      status: "success",
      details: "Interactive login",
    });

    return res.redirect("/dashboard");
  } catch (error) {
    return renderLogin(req, res, {
      flash: {
        type: "error",
        message: error.message || "Login failed.",
      },
    });
  }
});

app.get("/dashboard", requireAuth, async (req, res) => {
  try {
    const stats = await countDashboardStats();

    return res.render("dashboard", {
      title: "Dashboard",
      pageId: "dashboard",
      stats,
      user: req.session.user,
      error: null,
    });
  } catch (error) {
    console.error("Dashboard error:", error);
    return res.render("dashboard", {
      title: "Dashboard",
      pageId: "dashboard",
      stats: null,
      user: req.session.user,
      error: "Failed to load dashboard.",
    });
  }
});

app.get("/red-team", requireRedTeam, (req, res) => renderRedTeam(req, res));

app.post("/red-team/run", requireRedTeam, upload.single("artifact"), async (req, res) => {
  const moduleKey = sanitizeText(req.body.moduleKey);
  const activeModule = getRedModuleByKey(moduleKey);

  try {
    if (!activeModule) {
      throw new Error("Choose a valid red-team module.");
    }

    const result = await executeRedModule(moduleKey, {
      target: req.body.target,
      auxInput: req.body.auxInput,
      file: req.file || null,
      user: req.session.user,
    });

    await logActivity({
      userId: req.session.user.id,
      action: `red_module:${moduleKey}`,
      target: sanitizeText(req.body.target) || activeModule.title,
      status: "success",
      details: "Module executed successfully.",
    });

    return renderRedTeam(req, res, {
      moduleKey,
      result,
      flash: {
        type: "success",
        message: `${activeModule.title} completed.`,
      },
    });
  } catch (error) {
    await logActivity({
      userId: req.session.user.id,
      action: `red_module:${moduleKey || "unknown"}`,
      target: sanitizeText(req.body.target) || null,
      status: "error",
      details: error.message,
    }).catch(() => {});

    return renderRedTeam(req, res, {
      moduleKey,
      statusCode: 400,
      flash: {
        type: "error",
        message: error.message || "Red-team module execution failed.",
      },
    });
  }
});

app.get("/blue-team", requireBlueTeam, (req, res) => renderBlueTeam(req, res));

app.post("/blue-team/run", requireBlueTeam, async (req, res) => {
  const moduleKey = sanitizeText(req.body.moduleKey);
  const activeModule = getBlueModuleByKey(moduleKey);

  try {
    if (!activeModule) {
      throw new Error("Choose a valid blue-team module.");
    }

    const result = await executeBlueModule(moduleKey, {
      target: req.body.target,
      auxInput: req.body.auxInput,
      user: req.session.user,
    });

    await logActivity({
      userId: req.session.user.id,
      action: `blue_module:${moduleKey}`,
      target: sanitizeText(req.body.target) || activeModule.title,
      status: "success",
      details: "Module executed successfully.",
    });

    return renderBlueTeam(req, res, {
      moduleKey,
      result,
      flash: {
        type: "success",
        message: `${activeModule.title} completed.`,
      },
    });
  } catch (error) {
    await logActivity({
      userId: req.session.user.id,
      action: `blue_module:${moduleKey || "unknown"}`,
      target: sanitizeText(req.body.target) || null,
      status: "error",
      details: error.message,
    }).catch(() => {});

    return renderBlueTeam(req, res, {
      moduleKey,
      statusCode: 400,
      flash: {
        type: "error",
        message: error.message || "Blue-team module execution failed.",
      },
    });
  }
});

app.get("/admin/users", requireAdmin, async (req, res) => {
  const selectedUserId = parsePositiveInt(req.query.userId, 0);

  try {
    const users = await listUsers();
    const selectedUser = selectedUserId ? await findUserById(selectedUserId) : null;
    const userActivity = selectedUser
      ? await fetchActivityLogsByUserId(selectedUser.id, 200)
      : [];

    return res.render("admin-users", {
      title: "Users",
      pageId: "admin-users",
      user: req.session.user,
      users,
      selectedUser,
      userActivity,
    });
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to load users.");
    return res.redirect("/dashboard");
  }
});

app.post("/admin/users/:id/update", requireAdmin, async (req, res) => {
  const userId = parsePositiveInt(req.params.id, 0);
  const username = sanitizeText(req.body.username);
  const email = normalizeEmail(req.body.email);
  const role = sanitizeText(req.body.role);
  const newPassword = String(req.body.newPassword || "");

  try {
    if (!userId) {
      throw new Error("Invalid user id.");
    }

    validateAdminUserUpdate({ username, email, role, newPassword });

    await updateUserById(userId, {
      username,
      email,
      role,
      newPassword,
    });

    await logActivity({
      userId: req.session.user.id,
      action: "admin:update_user",
      target: String(userId),
      status: "success",
      details: `Updated user ${username}.`,
    });

    setFlash(req, "success", "User updated successfully.");
    return res.redirect(`/admin/users?userId=${userId}`);
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to update user.");
    return res.redirect(`/admin/users?userId=${userId}`);
  }
});

app.post("/admin/users/:id/delete", requireAdmin, async (req, res) => {
  const userId = parsePositiveInt(req.params.id, 0);

  try {
    if (!userId) {
      throw new Error("Invalid user id.");
    }

    if (userId === req.session.user.id) {
      throw new Error("You cannot delete the account you are currently signed into.");
    }

    await deleteUserById(userId);
    await logActivity({
      userId: req.session.user.id,
      action: "admin:delete_user",
      target: String(userId),
      status: "success",
      details: "User deleted.",
    });

    setFlash(req, "success", "User deleted successfully.");
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to delete user.");
  }

  return res.redirect("/admin/users");
});

app.get("/admin/logs", requireAdmin, async (req, res) => {
  const limit = Math.min(parsePositiveInt(req.query.limit, 200), 1000);

  try {
    const [logs, users] = await Promise.all([
      fetchActivityLogs(limit),
      listUsers(),
    ]);

    return res.render("admin-logs", {
      title: "Logs",
      pageId: "admin-logs",
      user: req.session.user,
      limit,
      logs,
      users,
    });
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to load logs.");
    return res.redirect("/dashboard");
  }
});

app.post("/admin/logs/:id/delete", requireAdmin, async (req, res) => {
  const logId = parsePositiveInt(req.params.id, 0);
  const limit = Math.min(parsePositiveInt(req.body.limit, 200), 1000);

  try {
    if (!logId) {
      throw new Error("Invalid log id.");
    }

    await deleteActivityLogById(logId);
    await logActivity({
      userId: req.session.user.id,
      action: "admin:delete_log",
      target: String(logId),
      status: "success",
      details: "Log entry deleted.",
    });

    setFlash(req, "success", "Log entry deleted.");
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to delete log entry.");
  }

  return res.redirect(`/admin/logs?limit=${limit}`);
});

app.post("/admin/logs/clear", requireAdmin, async (req, res) => {
  const limit = Math.min(parsePositiveInt(req.body.limit, 200), 1000);

  try {
    await clearActivityLogs();
    await logActivity({
      userId: req.session.user.id,
      action: "admin:clear_logs",
      target: "activity_logs",
      status: "success",
      details: "All activity logs cleared.",
    });

    setFlash(req, "success", "All logs cleared.");
  } catch (error) {
    setFlash(req, "error", error.message || "Failed to clear logs.");
  }

  return res.redirect(`/admin/logs?limit=${limit}`);
});

app.post("/logout-beacon", async (req, res) => {
  const sessionUser = req.session?.user || null;

  try {
    if (sessionUser) {
      await logActivity({
        userId: sessionUser.id,
        action: "logout",
        target: sessionUser.username,
        status: "success",
        details: "Session ended by page close/unload.",
      }).catch(() => {});
    }

    await destroySession(req);
    res.clearCookie(sessionCookieName);
    return res.status(204).end();
  } catch {
    return res.status(204).end();
  }
});

app.get("/logout", async (req, res) => {
  const sessionUser = req.session?.user || null;
  const reason = req.query.reason === "inactive" ? "inactive" : "logout";

  if (sessionUser) {
    await logActivity({
      userId: sessionUser.id,
      action: "logout",
      target: sessionUser.username,
      status: "success",
      details: reason === "inactive" ? "Session expired due to inactivity." : "Manual logout.",
    }).catch(() => {});
  }

  await destroySession(req).catch(() => {});
  res.clearCookie(sessionCookieName);
  return res.redirect(`/login?reason=${reason}`);
});

app.use((req, res) => {
  res.status(404).render("index", {
    title: "Not Found",
    pageId: "landing",
  });
});

const PORT = process.env.PORT || 3000;

async function startServer() {
  await initDb();

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on port ${PORT}`);
  });
}

if (require.main === module) {
  startServer().catch((error) => {
    console.error("Server failed to start:", error);
    process.exit(1);
  });
}

module.exports = {
  app,
  startServer,
};
