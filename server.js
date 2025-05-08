const express = require('express');
const app = express();

app.use(express.json());

// Webhook endpoint to receive sale data
app.post('/webhook', (req, res) => {
  const { bdeName, product, managerName } = req.body;

  if (!bdeName || !product || !managerName) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  console.log('Received sale data:', { bdeName, product, managerName });

  res.status(200).json({ message: 'Webhook received successfully' });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
