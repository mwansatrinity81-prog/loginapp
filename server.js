const http = require("http");
const fs = require("fs");
const crypto = require("crypto");

// Only these files can be requested
const files = {
  "/": { file: "index.html", type: "text/html" },
  "/style.css": { file: "style.css", type: "text/css" },
  "/app.js": { file: "app.js", type: "text/javascript" }
};

const sessions = new Map(); // token -> username
const attempts = new Map(); // key -> { count, lockedUntil }
const MAX_ATTEMPTS = 5;
const LOCK_MS = 60 * 1000;
const MAX_USERS = 200;

// Set to "true" on the hosting service, not on your PC
const HOSTED = process.env.HOSTED === "true";

function sendJson(res, status, data) {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(data));
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function loadUsers() {
  try {
    return JSON.parse(fs.readFileSync("users.json", "utf8"));
  } catch (error) {
    return [];
  }
}

function saveUsers(users) {
  fs.writeFileSync("users.json", JSON.stringify(users, null, 2));
}

// Turn a password + salt into a hash
function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString("hex");
}

function readBody(req, callback) {
  let body = "";
  req.on("data", function (chunk) {
    body += chunk;
    if (body.length > 10000) {
      req.destroy(); // too big
    }
  });
  req.on("end", function () {
    callback(body);
  });
}

// Read the session token from the cookie
function getSessionToken(req) {
  const header = req.headers.cookie || "";
  const parts = header.split(";");
  for (let i = 0; i < parts.length; i++) {
    const pair = parts[i].trim().split("=");
    if (pair[0] === "session" && sessions.has(pair[1])) {
      return pair[1];
    }
  }
  return null;
}

function getSessionUser(req) {
  const token = getSessionToken(req);
  return token ? sessions.get(token) : null;
}

const server = http.createServer(function (req, res) {
  // Registration
  if (req.method === "POST" && req.url === "/register") {
    readBody(req, function (body) {
      let data;
      try {
        data = JSON.parse(body);
      } catch (error) {
        return sendJson(res, 400, { ok: false, error: "Bad data." });
      }

      const username = String(data.username || "").trim();
      const password = String(data.password || "");

      if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) {
        return sendJson(res, 400, { ok: false, error: "Username must be 3 to 20 letters, numbers or underscores." });
      }
      if (password.length < 8 || password.length > 100) {
        return sendJson(res, 400, { ok: false, error: "Password must be 8 to 100 characters." });
      }

      const users = loadUsers();

      if (users.length >= MAX_USERS) {
        return sendJson(res, 503, { ok: false, error: "Registration is closed for this demo." });
      }

      const taken = users.some(function (u) {
        return u.username.toLowerCase() === username.toLowerCase();
      });
      if (taken) {
        return sendJson(res, 409, { ok: false, error: "That username is already taken." });
      }

      const salt = crypto.randomBytes(16).toString("hex");
      const hash = hashPassword(password, salt);

      users.push({ username: username, salt: salt, hash: hash });
      saveUsers(users);

      sendJson(res, 200, { ok: true });
    });
    return;
  }

  // Login
  if (req.method === "POST" && req.url === "/login") {
    readBody(req, function (body) {
      let data;
      try {
        data = JSON.parse(body);
      } catch (error) {
        return sendJson(res, 400, { ok: false, error: "Bad data." });
      }

      const username = String(data.username || "").trim();
      const password = String(data.password || "");

      // On a host, all visitors share the host's address, so lock by username only
      const key = HOSTED
        ? username.toLowerCase()
        : req.socket.remoteAddress + ":" + username.toLowerCase();

      // Is this user locked out?
      const record = attempts.get(key);
      if (record && record.lockedUntil > Date.now()) {
        return sendJson(res, 429, { ok: false, error: "Too many failed attempts. Try again in a minute." });
      }

      const users = loadUsers();
      const user = users.find(function (u) {
        return u.username.toLowerCase() === username.toLowerCase();
      });

      // Always do the hashing work, even for unknown users, so timing does not give them away
      const salt = user ? user.salt : "00000000000000000000000000000000";
      const hash = hashPassword(password.slice(0, 100), salt);

      let ok = false;
      if (user && password.length <= 100) {
        ok = crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(user.hash, "hex"));
      }

      if (!ok) {
        const rec = attempts.get(key) || { count: 0, lockedUntil: 0 };
        rec.count++;
        if (rec.count >= MAX_ATTEMPTS) {
          rec.lockedUntil = Date.now() + LOCK_MS;
          rec.count = 0;
        }
        attempts.set(key, rec);
        return sendJson(res, 401, { ok: false, error: "Wrong username or password." });
      }

      // Success: clear failed attempts and create a session
      attempts.delete(key);
      const token = crypto.randomBytes(32).toString("hex");
      sessions.set(token, user.username);

      res.writeHead(200, {
        "Content-Type": "application/json",
        "Set-Cookie": "session=" + token + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600" + (HOSTED ? "; Secure" : "")
      });
      res.end(JSON.stringify({ ok: true }));
    });
    return;
  }

  // Page that only logged-in users can see
  if (req.method === "GET" && req.url === "/dashboard") {
    const user = getSessionUser(req);
    if (!user) {
      res.writeHead(302, { Location: "/" });
      res.end();
      return;
    }

    let html = "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Dashboard</title></head>";
    html += "<body style='font-family: Arial, sans-serif; max-width: 500px; margin: 60px auto;'>";
    html += "<h1>Welcome, " + escapeHtml(user) + "!</h1>";
    html += "<p>You are logged in. Only logged-in users can see this page.</p>";
    html += "<form method='POST' action='/logout'><button type='submit'>Log out</button></form>";
    html += "</body></html>";

    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store" });
    res.end(html);
    return;
  }

  // Logout
  if (req.method === "POST" && req.url === "/logout") {
    const token = getSessionToken(req);
    if (token) {
      sessions.delete(token);
    }
    res.writeHead(302, {
      Location: "/",
      "Set-Cookie": "session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0"
    });
    res.end();
    return;
  }

  // Serve the page files
  const route = files[req.url];
  if (req.method === "GET" && route) {
    res.writeHead(200, { "Content-Type": route.type });
    res.end(fs.readFileSync(route.file));
    return;
  }

  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("Not found");
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, function () {
  console.log("Server running on port " + PORT);
});