require('dotenv').config();
const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const connectDB = require('./config/db');
const { closeAll } = require('./db/connectionManager');
const logError = require('./utils/errorLogger');
const { startSummaryWorker, stopSummaryWorker } = require('./workers/summaryWorker');
const passport = require('./config/passport');
const corsMiddleware = require('./middleware/corsMiddleware');

const authRoutes = require('./routes/auth');
const githubRoutes = require('./routes/github');
const webhookRoutes = require('./routes/webhook');
const installationSummaryRoutes = require('./routes/installationSummaryRoutes');
const repositoryRoutes = require('./routes/repositoryRoutes');
const organizationRoutes = require('./routes/organization');
const scansRoutes = require('./routes/scans');



const validateContentType = require('./middleware/validator/validateContentType');
const sanitizeInput = require('./middleware/validator/sanitizeInput');
const blockParameterPollution = require('./middleware/validator/blockParameterPollution');

const app = express();
const PORT = process.env.PORT || 5000;

app.set('trust proxy', 1);

app.use(corsMiddleware);
app.use(blockParameterPollution);
app.use(cookieParser());
app.use(passport.initialize());

// GitHub puts the installation's whole repository list inside `installation` and
// `installation_repositories` payloads. An org installed on "All repositories"
// with a few thousand repos produces a body of several MB, and body-parser's
// 100kb default answered those deliveries with 413 — GitHub marked the delivery
// failed, so the installation was never recorded and the org never appeared in
// Zyloch. GitHub caps a single delivery at 25MB, so accept up to that.
const WEBHOOK_BODY_LIMIT = process.env.GITHUB_WEBHOOK_BODY_LIMIT || '25mb';

app.use('/webhook/github', bodyParser.json({
  limit: WEBHOOK_BODY_LIMIT,
  verify: (req, res, buf) => {
    req.rawBody = buf.toString();
  }
}));

app.use(bodyParser.json({ limit: '100kb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100kb' }));

app.use(sanitizeInput);


app.use('/auth', validateContentType(['application/json']), authRoutes);

app.use('/api/installations', githubRoutes);

app.use('/webhook', webhookRoutes);

app.use('/api/installation-summary', installationSummaryRoutes);
app.use('/api/repositories', repositoryRoutes);
app.use('/api/organization', organizationRoutes);
app.use('/api/scans', scansRoutes);

app.get('/', (req, res) => {
  res.send(`
    <div style="font-family: Arial, sans-serif; text-align:center; margin-top:50px;">
      <h1 style="color:#1E90FF;">Welcome to Zyloch 🚀</h1>
      <p style="color:#333;">Zyloch API is live and operational!</p>
      <a href="/docs" style="color:#1E90FF; text-decoration:none;">View API Docs</a>
    </div>
  `);
});

app.get('/health', (req, res) => {
  res.json({ ok: true, timestamp: new Date().toISOString() });
});

app.use((err, req, res, next) => {
  const statusCode = err.statusCode || err.status || 500;

  // A rejected body is invisible in the app logs otherwise — the sender only
  // sees a bare 413. Name the limit that was hit so it can be raised knowingly.
  if (err.type === 'entity.too.large') {
    console.error(
      `[BodyParser] Rejected ${req.method} ${req.originalUrl}: payload exceeds the configured limit ` +
        `(${req.originalUrl.startsWith('/webhook/github') ? WEBHOOK_BODY_LIMIT : '100kb'})`
    );
  }

  // Expected pre-login 401s (auth probes before sign-in) are not server errors
  if (statusCode !== 401) {
    console.error('Error:', err.message);
    logError(err, req);
  }

  res.status(statusCode).json({
    status: 'error',
    message: err.message || 'Unexpected error occurred. Please try again later.',
    // Machine-readable reason, when the thrower set one. The dashboard needs to
    // tell "you must choose repositories first" (REPO_SELECTION_REQUIRED) apart
    // from an ordinary failure, and a message string is not something to branch on.
    ...(err.code ? { code: err.code } : {}),
    ...(err.selection ? { selection: err.selection } : {}),
  });
});

let server;
let summaryWorker;

async function start() {
  // Connect the shared cluster + bootstrap the control plane before serving.
  await connectDB();
  summaryWorker = startSummaryWorker();

  server = app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Environment: ${process.env.NODE_ENV}`);
  });
}

async function shutdown(signal) {
  console.log(`\n[shutdown] Received ${signal}, closing gracefully...`);
  try {
    if (server) {
      await new Promise((resolve) => server.close(resolve));
    }
    await stopSummaryWorker();
    await closeAll();
    console.log('[shutdown] Clean exit');
    process.exit(0);
  } catch (err) {
    console.error('[shutdown] Error during shutdown:', err.message);
    process.exit(1);
  }
}

['SIGINT', 'SIGTERM'].forEach((signal) => {
  process.on(signal, () => shutdown(signal));
});

start().catch((err) => {
  console.error('[startup] Fatal error during startup:', err.message);
  process.exit(1);
});

module.exports = app;