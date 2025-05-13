require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sendgridMail = require('@sendgrid/mail');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');

const app = express();

// Enable trust proxy to handle X-Forwarded-For header correctly
app.set('trust proxy', true);

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// Configure CORS using EXTENSION_ID from environment
const EXTENSION_ID = process.env.EXTENSION_ID;
if (!EXTENSION_ID) {
  console.error('EXTENSION_ID environment variable is not set');
  process.exit(1);
}
app.use(cors({
  origin: `chrome-extension://${EXTENSION_ID}`
}));

// Configure webhook token from environment
const WEBHOOK_TOKEN = process.env.WEBHOOK_TOKEN;
if (!WEBHOOK_TOKEN) {
  console.error('WEBHOOK_TOKEN environment variable is not set');
  process.exit(1);
}

// Configure SendGrid using environment variable
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
if (!SENDGRID_API_KEY) {
  console.error('SendGrid API key is missing in environment variables');
  process.exit(1);
}
sendgridMail.setApiKey(SENDGRID_API_KEY);

// Rate limiting for API endpoints
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100 // Limit each IP to 100 requests per window
});
app.use('/request-otp', limiter);
app.use('/verify-otp', limiter);

// Track WebSocket connections per IP
const connectionsPerIp = new Map();
const MAX_CONNECTIONS_PER_IP = 5;

// Middleware to validate token (Bearer token in Authorization header)
const validateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Bearer token' });
  }
  const token = authHeader.split(' ')[1];
  if (!token || !validateTokenFormat(token)) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
  req.authToken = token;
  next();
};

// Middleware to validate webhook Bearer token
const validateWebhookToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Bearer token' });
  }
  const token = authHeader.split(' ')[1];
  if (token !== WEBHOOK_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized: Invalid Bearer token' });
  }
  next();
};

// Validate token format (UUID)
function validateTokenFormat(token) {
  return token && /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(token);
}

// Store OTPs temporarily (in-memory, expires in 5 minutes)
const otps = new Map();

// Generate 6-digit OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// WebSocket connection handling
const clients = new Map(); // Map to store authenticated clients

wss.on('connection', (ws, req) => {
  // Validate Origin header
  const origin = req.headers.origin;
  if (origin !== `chrome-extension://${EXTENSION_ID}`) {
    ws.close(1008, 'Unauthorized Origin');
    return;
  }

  // Rate limit WebSocket connections by IP
  const ip = req.socket.remoteAddress;
  const connectionCount = connectionsPerIp.get(ip) || 0;
  if (connectionCount >= MAX_CONNECTIONS_PER_IP) {
    ws.close(1008, 'Too many connections from this IP');
    return;
  }
  connectionsPerIp.set(ip, connectionCount + 1);

  // Validate token in WebSocket URL
  const urlParams = new URLSearchParams(req.url.split('?')[1]);
  const token = urlParams.get('token');
  if (!token || !validateTokenFormat(token)) {
    ws.close(1008, 'Unauthorized: Invalid token');
    return;
  }

  // Store client with token
  clients.set(ws, { token });

  ws.on('message', (message) => {
    const data = JSON.parse(message);
    if (data.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
    const newCount = (connectionsPerIp.get(ip) || 1) - 1;
    if (newCount <= 0) {
      connectionsPerIp.delete(ip);
    } else {
      connectionsPerIp.set(ip, newCount);
    }
  });
});

// Webhook endpoint to receive sale data
app.post('/webhook', validateWebhookToken, (req, res) => {
  const { type, bdeName, product, managerName, message, email } = req.body;

  if (!type) {
    return res.status(400).json({ error: 'Missing type field' });
  }

  let saleData;
  if (type === 'sale_made') {
    if (!bdeName || !product || !managerName) {
      return res.status(400).json({ error: 'Missing required fields for sale_made' });
    }
    saleData = {
      type: 'sale_made',
      bdeName,
      product,
      managerName,
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9)
    };
  } else if (type === 'notification') {
    if (!message) {
      return res.status(400).json({ error: 'Missing message field for notification' });
    }
    saleData = {
      type: 'notification',
      message,
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9)
    };
  } else if (type === 'private') {
    if (!email || !message) {
      return res.status(400).json({ error: 'Missing email or message field for private type' });
    }
    saleData = {
      type: 'private',
      email,
      message,
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9)
    };
  } else {
    return res.status(400).json({ error: 'Invalid type' });
  }

  clients.forEach((clientData, client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(saleData));
    }
  });

  console.log('Webhook received:', { type, bdeName, product, managerName, message, email });
  res.status(200).json({ message: 'Webhook received successfully' });
});

// Ping endpoint to keep Render awake
app.get('/ping', (req, res) => {
  res.status(200).json({ status: 'alive' });
});

// Request OTP
app.post('/request-otp', (req, res, next) => {
  // Allow first-time OTP request without a token
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    validateToken(req, res, next);
  } else {
    next();
  }
}, (req, res) => {
  const { email } = req.body;
  if (!email || !email.endsWith('@codingninjas.com')) {
    return res.status(400).json({ error: 'Invalid email. Must be @codingninjas.com' });
  }

  const otp = generateOTP();
  otps.set(email, { otp, expires: Date.now() + 5 * 60 * 1000 });

  const msg = {
    to: email,
    from: 'noreply@codingninjas.com',
    subject: 'Your OTP for Sales Notification Extension',
    text: `Your OTP is ${otp}. It expires in 5 minutes.`,
  };

  sendgridMail.send(msg)
    .then(() => {
      console.log(`OTP sent successfully to ${email}`);
      res.status(200).json({ message: 'OTP sent successfully' });
    })
    .catch((error) => {
      console.error('Failed to send OTP:', error.response ? error.response.body : error.message);
      res.status(500).json({ error: 'Failed to send OTP' });
    });
});

// Verify OTP
app.post('/verify-otp', (req, res, next) => {
  // Allow first-time OTP verification without a token
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    validateToken(req, res, next);
  } else {
    next();
  }
}, (req, res) => {
  const { email, otp } = req.body;
  const stored = otps.get(email);

  if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  otps.delete(email);
  const token = uuidv4();
  console.log(`OTP verified for ${email}, token: ${token}`);
  res.status(200).json({ message: 'OTP verified successfully', token, email });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
