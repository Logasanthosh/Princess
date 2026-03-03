const express = require('express');
const fs = require('fs');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// ---------- Configuration ----------
// Change this to a strong secret for accessing the admin logs
const ADMIN_PASSWORD = 'change-me-to-a-strong-password';

// Log file path
const LOG_FILE = path.join(__dirname, 'login-attempts.log');

// ---------- Middleware ----------
app.use(express.json());
app.use(express.static(__dirname)); // serve index.html and static assets

// ---------- Helper ----------
function getClientIP(req) {
  // Support proxies (e.g. Nginx, Cloudflare)
  const forwarded = req.headers['x-forwarded-for'];
  if (forwarded) {
    return forwarded.split(',')[0].trim();
  }
  return req.socket.remoteAddress || 'unknown';
}

// ---------- Routes ----------

// POST /api/log-attempt  — called by the frontend on every login attempt
app.post('/api/log-attempt', (req, res) => {
  const { success } = req.body;

  const entry = {
    ip: getClientIP(req),
    timestamp: new Date().toISOString(),
    success: Boolean(success),
    userAgent: req.headers['user-agent'] || 'unknown'
  };

  const logLine = JSON.stringify(entry) + '\n';

  fs.appendFile(LOG_FILE, logLine, (err) => {
    if (err) {
      console.error('Failed to write log:', err);
      return res.status(500).json({ error: 'Logging failed' });
    }
    console.log(`[LOGIN ${entry.success ? 'SUCCESS' : 'FAILURE'}] IP: ${entry.ip} at ${entry.timestamp}`);
    return res.json({ status: 'logged' });
  });
});

// GET /api/logs  — admin endpoint to view all login attempts (protected)
app.get('/api/logs', (req, res) => {
  // Simple token-based auth via query param: /api/logs?token=YOUR_ADMIN_PASSWORD
  const token = req.query.token;
  if (token !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized. Provide ?token=YOUR_ADMIN_PASSWORD' });
  }

  fs.readFile(LOG_FILE, 'utf8', (err, data) => {
    if (err) {
      if (err.code === 'ENOENT') {
        return res.json({ attempts: [] });
      }
      return res.status(500).json({ error: 'Could not read logs' });
    }

    const attempts = data
      .trim()
      .split('\n')
      .filter(line => line.length > 0)
      .map(line => {
        try { return JSON.parse(line); }
        catch { return null; }
      })
      .filter(Boolean);

    return res.json({ total: attempts.length, attempts });
  });
});

// GET /api/logs/clear  — admin endpoint to clear logs
app.get('/api/logs/clear', (req, res) => {
  const token = req.query.token;
  if (token !== ADMIN_PASSWORD) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  fs.writeFile(LOG_FILE, '', (err) => {
    if (err) return res.status(500).json({ error: 'Could not clear logs' });
    return res.json({ status: 'Logs cleared' });
  });
});

// ---------- Start ----------
app.listen(PORT, () => {
  console.log(`✅ Server running at http://localhost:${PORT}`);
  console.log(`📋 View login logs at http://localhost:${PORT}/api/logs?token=${ADMIN_PASSWORD}`);
});
