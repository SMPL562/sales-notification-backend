const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

app.use(express.json());

// WebSocket connection handling
const clients = new Set();
wss.on('connection', (ws) => {
  clients.add(ws);

  ws.on('message', (message) => {
    const data = JSON.parse(message);
    if (data.type === 'ping') {
      ws.send(JSON.stringify({ type: 'pong' }));
    }
  });

  ws.on('close', () => {
    clients.delete(ws);
  });
});

// Webhook endpoint to receive sale data
app.post('/webhook', (req, res) => {
  const { bdeName, product, managerName } = req.body;

  if (!bdeName || !product || !managerName) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  const saleData = {
    bdeName,
    product,
    managerName,
    messageId: Date.now().toString() + '-' + Math.random().toString(36).substr(2, 9) // Unique message ID
  };

  clients.forEach((client) => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(JSON.stringify(saleData));
    }
  });

  res.status(200).json({ message: 'Webhook received successfully' });
});

// Ping endpoint to keep Render awake
app.get('/ping', (req, res) => {
  res.status(200).json({ status: 'alive' });
});

// Start the server
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
