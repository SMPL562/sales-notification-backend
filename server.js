require('dotenv').config();
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const sendgridMail = require('@sendgrid/mail');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs').promises;
const url = require('url');

const app = express();
app.set('trust proxy', 1);
const server = http.createServer(app);

// Enhanced Memory Management Classes (keep same as before)
class LRUCache {
  constructor(maxSize = 1000) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (this.cache.has(key)) {
      const value = this.cache.get(key);
      this.cache.delete(key);
      this.cache.set(key, value);
      return value;
    }
    return null;
  }

  set(key, value) {
    if (this.cache.has(key)) {
      this.cache.delete(key);
    } else if (this.cache.size >= this.maxSize) {
      const firstKey = this.cache.keys().next().value;
      this.cache.delete(firstKey);
    }
    this.cache.set(key, value);
  }

  delete(key) {
    this.cache.delete(key);
  }

  get size() {
    return this.cache.size;
  }

  keys() {
    return this.cache.keys();
  }

  // ADD THIS METHOD:
  entries() {
    return this.cache.entries();
  }

  clear() {
    this.cache.clear();
  }
}

class FileBackedStorage {
  constructor(filename, maxMemorySize = 100) {
    this.filename = filename;
    this.maxMemorySize = maxMemorySize;
    this.memoryCache = new Map();
    this.dirty = false;
    this.lastSave = Date.now();
    
    this.loadFromFile();
    setInterval(() => this.saveToFile(), 60000);
  }

  async loadFromFile() {
    try {
      const data = await fs.readFile(this.filename, 'utf8');
      const parsed = JSON.parse(data);
      this.memoryCache = new Map(parsed);
      console.log(`Loaded ${this.memoryCache.size} entries from ${this.filename}`);
    } catch (error) {
      console.log(`No existing file ${this.filename}, starting fresh`);
    }
  }

  async saveToFile() {
    if (!this.dirty) return;
    
    try {
      const data = JSON.stringify([...this.memoryCache.entries()]);
      await fs.writeFile(this.filename, data);
      this.dirty = false;
      this.lastSave = Date.now();
    } catch (error) {
      console.error(`Failed to save to ${this.filename}:`, error);
    }
  }

  set(key, value) {
    if (this.memoryCache.size >= this.maxMemorySize && !this.memoryCache.has(key)) {
      const firstKey = this.memoryCache.keys().next().value;
      this.memoryCache.delete(firstKey);
    }
    
    this.memoryCache.set(key, value);
    this.dirty = true;
  }

  get(key) {
    return this.memoryCache.get(key);
  }

  delete(key) {
    if (this.memoryCache.delete(key)) {
      this.dirty = true;
    }
  }

  get size() {
    return this.memoryCache.size;
  }
}

class ClientManager {
  constructor() {
    this.clients = new Map();
    this.maxQueueSize = 10;
    this.maxClients = 50;
  }

  addClient(ws, clientData) {
    if (this.clients.size >= this.maxClients) {
      const oldestWs = this.clients.keys().next().value;
      this.removeClient(oldestWs);
    }

    clientData.queue = clientData.queue || [];
    this.clients.set(ws, clientData);
  }

  removeClient(ws) {
    this.clients.delete(ws);
  }

  addToQueue(ws, notification) {
    const clientData = this.clients.get(ws);
    if (!clientData) return false;

    if (clientData.queue.length >= this.maxQueueSize) {
      clientData.queue.shift();
    }
    
    clientData.queue.push(notification);
    return true;
  }

  getClient(ws) {
    return this.clients.get(ws);
  }

  get size() {
    return this.clients.size;
  }

  forEach(callback) {
    this.clients.forEach(callback);
  }
}

class MemoryManager {
  constructor() {
    this.otps = new Map();
    this.startCleanupRoutines();
  }

  startCleanupRoutines() {
    setInterval(() => {
      const now = Date.now();
      for (const [email, data] of this.otps.entries()) {
        if (now > data.expires) {
          this.otps.delete(email);
        }
      }
    }, 120000);

    setInterval(() => {
      const now = Date.now();
      const maxAge = 24 * 60 * 60 * 1000;
      
      for (const [token, timestamp] of lastConnectionTime.entries()) {
        if (now - timestamp > maxAge) {
          lastConnectionTime.delete(token);
          lastPingTime.delete(token);
        }
      }
    }, 600000);

    setInterval(() => {
      const memUsage = process.memoryUsage();
      const memUsageMB = Math.round(memUsage.heapUsed / 1024 / 1024);
      
      if (memUsageMB > 200) {
        console.warn(`High memory usage: ${memUsageMB}MB`);
        this.triggerCleanup();
      }
    }, 300000);
  }

  triggerCleanup() {
    if (global.gc) {
      global.gc();
    }
    
    if (connectionsPerToken.size > 50) {
      const keysToDelete = Array.from(connectionsPerToken.keys()).slice(0, 10);
      keysToDelete.forEach(key => connectionsPerToken.delete(key));
    }
  }

  addOTP(email, otp, expires) {
    if (this.otps.size >= 1000) {
      const oldestEntry = this.otps.keys().next().value;
      this.otps.delete(oldestEntry);
    }
    this.otps.set(email, { otp, expires });
  }

  getOTP(email) {
    return this.otps.get(email);
  }

  deleteOTP(email) {
    this.otps.delete(email);
  }
}

// Initialize managers
const memoryManager = new MemoryManager();
const clientManager = new ClientManager();
const connectionsPerToken = new LRUCache(100);
const lastConnectionTime = new LRUCache(500);
const lastPingTime = new LRUCache(500);
const persistentTokens = new FileBackedStorage('tokens.json', 100);

// Environment validation
const requiredEnvVars = ['EXTENSION_ID', 'WEBHOOK_TOKEN', 'JWT_SECRET', 'SENDGRID_API_KEY'];
for (const envVar of requiredEnvVars) {
  if (!process.env[envVar]) {
    console.error(`${envVar} environment variable is not set`);
    process.exit(1);
  }
}

const { EXTENSION_ID, WEBHOOK_TOKEN, JWT_SECRET, SENDGRID_API_KEY } = process.env;

// Configure CORS
app.use(cors({
  origin: `chrome-extension://${EXTENSION_ID}`,
  credentials: true
}));

// Configure SendGrid
sendgridMail.setApiKey(SENDGRID_API_KEY);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { error: 'Too many requests, please try again later' }
});

app.use('/request-otp', limiter);
app.use('/verify-otp', limiter);

// Constants - RELAXED RATE LIMITS
const processedMessages = new Set();
const MAX_CONNECTIONS_PER_TOKEN = 1;
const MIN_CONNECTION_INTERVAL = 5000; // Reduced from 30000 to 5000 (5 seconds)
const MIN_PING_INTERVAL = 30000;
const TOKEN_EXPIRY_DAYS = 30;
const COOLDOWN_PERIOD = 30000;

// Express middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Set proper charset
app.use((req, res, next) => {
  res.charset = 'utf-8';
  next();
});

// Middleware functions
const validateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Bearer token' });
  }
  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).json({ error: 'Unauthorized: Invalid token' });
  }
  req.authToken = token;
  next();
};

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

// Utility functions
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

function validateJwtToken(token) {
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    return { email: decoded.email, expiry: decoded.exp * 1000 };
  } catch (error) {
    console.error('JWT validation error:', error.message);
    return null;
  }
}

// Create WebSocket server with relaxed rate limiting
const wss = new WebSocket.Server({ 
  server,
  path: '/ws',
  verifyClient: (info) => {
    try {
      // Verify origin
      const origin = info.origin;
      if (origin !== `chrome-extension://${EXTENSION_ID}`) {
        console.log('WebSocket connection rejected: Invalid origin', origin);
        return false;
      }

      // Parse URL to get token
      const parsedUrl = url.parse(info.req.url, true);
      const token = parsedUrl.query.token;
      
      if (!token) {
        console.log('WebSocket connection rejected: Missing token');
        return false;
      }

      // Validate JWT token
      const tokenData = validateJwtToken(token);
      if (!tokenData || Date.now() > tokenData.expiry) {
        console.log('WebSocket connection rejected: Invalid or expired token');
        return false;
      }

      // RELAXED connection throttling - only check if there's a very recent connection
      const lastConnTime = lastConnectionTime.get(token) || 0;
      const currentTime = Date.now();
      if (currentTime - lastConnTime < MIN_CONNECTION_INTERVAL) {
        console.log(`WebSocket connection rejected: Too frequent connections (${currentTime - lastConnTime}ms ago)`);
        return false;
      }

      // Store token data for later use
      info.req.tokenData = tokenData;
      info.req.token = token;
      
      return true;
    } catch (error) {
      console.error('Error in WebSocket verifyClient:', error);
      return false;
    }
  }
});

// WebSocket connection handling
wss.on('connection', (ws, req) => {
  const token = req.token;
  const tokenData = req.tokenData;
  
  if (!token || !tokenData) {
    ws.close(1008, 'Invalid connection data');
    return;
  }

  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  console.log(`WebSocket connected: ${tokenData.email}, IP: ${ip}`);

  // Close existing connection if any
  const existingWs = connectionsPerToken.get(token);
  if (existingWs && existingWs.readyState === WebSocket.OPEN) {
    console.log('Closing existing connection for token');
    existingWs.close(1000, 'Replaced by new connection');
  }

  // Update connection tracking
  const currentTime = Date.now();
  lastConnectionTime.set(token, currentTime);
  connectionsPerToken.set(token, ws);
  
  // Add client to manager
  clientManager.addClient(ws, {
    token,
    email: tokenData.email,
    queue: [],
    lastSentTime: 0,
    popupsEnabled: true
  });

  // Handle incoming messages
  ws.on('message', (message) => {
    try {
      const data = JSON.parse(message);
      
      switch (data.type) {
        case 'ping':
          const lastPing = lastPingTime.get(token) || 0;
          const now = Date.now();
          if (now - lastPing >= MIN_PING_INTERVAL) {
            lastPingTime.set(token, now);
            ws.send(JSON.stringify({ type: 'pong' }));
          }
          break;
          
        case 'requestNextNotification':
          const clientData = clientManager.getClient(ws);
          if (!clientData) return;

          const currentTime = Date.now();
          if (currentTime - clientData.lastSentTime < COOLDOWN_PERIOD) {
            ws.send(JSON.stringify({ 
              type: 'wait', 
              remaining: COOLDOWN_PERIOD - (currentTime - clientData.lastSentTime) 
            }));
            return;
          }

          if (clientData.queue.length > 0) {
            const nextNotification = clientData.queue.shift();
            ws.send(JSON.stringify(nextNotification));
            clientData.lastSentTime = Date.now();
            console.log('Sent queued notification to client');
          } else {
            ws.send(JSON.stringify({ type: 'noNotifications' }));
          }
          break;
          
        case 'updatePopupSettings':
          const client = clientManager.getClient(ws);
          if (client) {
            client.popupsEnabled = data.popupsEnabled;
            console.log(`Updated popup settings for client: ${data.popupsEnabled}`);
          }
          break;
          
        case 'keepAlive':
          ws.send(JSON.stringify({ type: 'keepAliveResponse' }));
          break;
          
        default:
          console.log('Unknown message type:', data.type);
      }
    } catch (error) {
      console.error('Error parsing WebSocket message:', error);
    }
  });

  // Handle connection close
  ws.on('close', (code, reason) => {
    console.log(`WebSocket disconnected: ${tokenData.email}, Code: ${code}, Reason: ${reason}`);
    
    // Cleanup
    clientManager.removeClient(ws);
    if (connectionsPerToken.get(token) === ws) {
      connectionsPerToken.delete(token);
    }
  });

  // Handle WebSocket errors
  ws.on('error', (error) => {
    console.error('WebSocket error for', tokenData.email, ':', error);
  });

  // Send welcome message
  ws.send(JSON.stringify({ 
    type: 'connected', 
    message: 'WebSocket connection established',
    email: tokenData.email
  }));
});

// Handle WebSocket server errors
wss.on('error', (error) => {
  console.error('WebSocket Server Error:', error);
});

// API Endpoints
app.get('/ping', (req, res) => {
  console.log(`Ping request from IP: ${req.ip}`);
  res.status(200).json({ 
    status: 'alive',
    timestamp: Date.now(),
    connections: connectionsPerToken.size
  });
});

app.get('/stats', (req, res) => {
  const memUsage = process.memoryUsage();
  res.json({
    memory: {
      used: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
      total: Math.round(memUsage.heapTotal / 1024 / 1024) + 'MB'
    },
    connections: connectionsPerToken.size,
    clients: clientManager.size,
    uptime: Math.round(process.uptime()),
    otps: memoryManager.otps.size
  });
});

app.post('/request-otp', (req, res, next) => {
  console.log(`Request-OTP from IP: ${req.ip}`);
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
  const expires = Date.now() + 5 * 60 * 1000;
  memoryManager.addOTP(email, otp, expires);

  const msg = {
    to: email,
    from: 'noreply@codingninjas.com',
    subject: 'Your OTP for Sales Notification Extension',
    text: `Your OTP is ${otp}. It expires in 5 minutes.`,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #f16222;">Sales Notification Extension</h2>
        <p>Your OTP is:</p>
        <h1 style="color: #f16222; font-size: 32px; text-align: center; background: #f5f5f5; padding: 20px; border-radius: 8px;">${otp}</h1>
        <p>This OTP expires in 5 minutes.</p>
        <p>If you didn't request this, please ignore this email.</p>
      </div>
    `
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

app.post('/verify-otp', (req, res, next) => {
  console.log(`Verify-OTP from IP: ${req.ip}`);
  const authHeader = req.headers['authorization'];
  if (authHeader && authHeader.startsWith('Bearer ')) {
    validateToken(req, res, next);
  } else {
    next();
  }
}, (req, res) => {
  const { email, otp } = req.body;
  const stored = memoryManager.getOTP(email);

  if (!stored || stored.otp !== otp || Date.now() > stored.expires) {
    return res.status(400).json({ error: 'Invalid or expired OTP' });
  }

  memoryManager.deleteOTP(email);
  
  const token = jwt.sign(
    { email },
    JWT_SECRET,
    { expiresIn: `${TOKEN_EXPIRY_DAYS}d` }
  );
  
  persistentTokens.set(token, { email, timestamp: Date.now() });
  
  console.log(`OTP verified for ${email}`);
  res.status(200).json({ message: 'OTP verified successfully', token, email });
});

app.post('/webhook', validateWebhookToken, (req, res) => {
  console.log(`Webhook request from IP: ${req.ip}`);
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
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now()
    };
  } else if (type === 'notification') {
    if (!message) {
      return res.status(400).json({ error: 'Missing message field for notification' });
    }
    saleData = {
      type: 'notification',
      message,
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now()
    };
  } else if (type === 'private') {
    if (!email || !message) {
      return res.status(400).json({ error: 'Missing email or message field for private type' });
    }
    saleData = {
      type: 'private',
      email,
      message,
      messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9),
      timestamp: Date.now()
    };
  } else {
    return res.status(400).json({ error: 'Invalid type' });
  }

  let sentCount = 0;
  let queuedCount = 0;

  clientManager.forEach((clientData, client) => {
    if (client.readyState === WebSocket.OPEN) {
      // For private messages, ensure the email matches
      if (saleData.type === 'private' && clientData.email !== saleData.email) {
        return;
      }

      // Check if popups are enabled for this client
      if (!clientData.popupsEnabled) {
        console.log(`Skipping notification for client (popups disabled)`);
        return;
      }

      const currentTime = Date.now();
      if (currentTime - clientData.lastSentTime < COOLDOWN_PERIOD) {
        clientManager.addToQueue(client, saleData);
        queuedCount++;
        console.log(`Notification queued for client`);
      } else {
        try {
          client.send(JSON.stringify(saleData));
          clientData.lastSentTime = currentTime;
          sentCount++;
          console.log(`Notification sent to client`);
        } catch (error) {
          console.error('Error sending notification:', error);
        }
      }
    }
  });

  console.log('Webhook processed:', { type, sentCount, queuedCount });
  res.status(200).json({ 
    message: 'Webhook received successfully',
    sent: sentCount,
    queued: queuedCount
  });
});

// Health check endpoint
app.get('/health', (req, res) => {
  const memUsage = process.memoryUsage();
  const isHealthy = memUsage.heapUsed < 400 * 1024 * 1024;
  
  res.status(isHealthy ? 200 : 503).json({
    status: isHealthy ? 'healthy' : 'unhealthy',
    memory: Math.round(memUsage.heapUsed / 1024 / 1024) + 'MB',
    connections: connectionsPerToken.size,
    uptime: process.uptime(),
    websocket: {
      clients: wss.clients.size,
      readyState: 'OPEN'
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({ error: 'Endpoint not found' });
});

// Graceful shutdown
const gracefulShutdown = async () => {
  console.log('Received shutdown signal, closing connections...');
  
  wss.clients.forEach(ws => {
    ws.close(1000, 'Server shutdown');
  });
  
  wss.close(() => {
    console.log('WebSocket server closed');
  });
  
  if (persistentTokens) {
    await persistentTokens.saveToFile();
  }
  
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

process.on('warning', (warning) => {
  if (warning.name === 'MaxListenersExceededWarning') {
    console.warn('MaxListenersExceededWarning detected, cleaning up...');
    memoryManager.triggerCleanup();
  }
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('Unhandled Rejection at:', promise, 'reason:', reason);
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Memory limit: 256MB`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`WebSocket path: /ws`);
  console.log(`Extension ID: ${EXTENSION_ID}`);
});
