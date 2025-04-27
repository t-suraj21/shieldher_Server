// Importing required modules
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();
const twilio = require("twilio");
const bodyParser = require("body-parser");
const http = require("http");
const socketIo = require("socket.io");

// Initialize Express app and Socket.io server
const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Middleware
app.use(cors());
app.use(express.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.log("MongoDB connection error:", err));

// Twilio setup
const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const twilioPhoneNumber = process.env.TWILIO_PHONE_NUMBER;
const client = new twilio(accountSid, authToken);

// Middleware to verify API Key for chatbot
const apiKeyMiddleware = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey || apiKey !== process.env.CHATBOT_API_KEY) {
    return res.status(401).json({ success: false, message: 'Unauthorized: Invalid API Key' });
  }
  next();
};

// User schema and model
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  emergencyContact: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// --------------------
// Routes
// --------------------

// Register route
app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password, emergencyContact } = req.body;
    const existingUser = await User.findOne({ email });
    if (existingUser) return res.status(400).json({ success: false, message: "User already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword, emergencyContact });
    await newUser.save();

    res.status(201).json({ success: true, message: "User registered successfully" });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// Login route
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ success: false, message: "Email and password are required" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ success: false, message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ success: false, message: "Invalid credentials" });

    const token = jwt.sign({ userId: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
    res.json({ success: true, message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ success: false, message: "Server error", error: err.message });
  }
});

// Profile route
app.get('/api/auth/profile', async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ success: false, message: 'No token provided' });
    }
    const token = authHeader.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.userId).select('-password');
    if (!user) return res.status(404).json({ success: false, message: 'User not found' });

    res.json({ success: true, user });
  } catch (err) {
    res.status(401).json({ success: false, message: 'Invalid token' });
  }
});

// Twilio Call route
app.post('/api/call', async (req, res) => {
  try {
    const { to, message, location } = req.body;

    if (!to || !message) {
      return res.status(400).json({ success: false, message: 'Phone number and message are required' });
    }

    const fullMessage = location ? `${message} Location: ${location}` : message;

    const call = await client.calls.create({
      to: to,
      from: twilioPhoneNumber,
      url: 'http://demo.twilio.com/docs/voice.xml',
    });

    await client.messages.create({
      to: to,
      from: twilioPhoneNumber,
      body: fullMessage,
    });

    res.status(200).json({ success: true, message: 'Call and message initiated successfully' });
  } catch (error) {
    console.error('Twilio error:', error);
    res.status(500).json({ success: false, message: 'Failed to initiate call and message', error: error.message });
  }
});

// Emergency Call route (mock example)
app.post('/api/emergency-call', async (req, res) => {
  const { caller, emergencyContacts } = req.body;

  if (!caller || !caller.name || !caller.number || !emergencyContacts || emergencyContacts.length === 0) {
    return res.status(400).json({ success: false, message: 'Invalid request data' });
  }

  console.log('Emergency Call Request Received:');
  console.log('Caller:', caller);
  console.log('Emergency Contacts:', emergencyContacts);

  for (let contact of emergencyContacts) {
    try {
      const call = await client.calls.create({
        to: contact,
        from: twilioPhoneNumber,
        url: 'http://demo.twilio.com/docs/voice.xml',
      });
      console.log(`Emergency call initiated to ${contact}, Call SID: ${call.sid}`);
    } catch (error) {
      console.error(`Error calling ${contact}:`, error);
    }
  }

  return res.json({ success: true, message: 'Emergency calls initiated successfully (mock).' });
});

// --------------------
// Chatbot route (with API Key middleware)
// --------------------
app.post("/api/chatbot", apiKeyMiddleware, async (req, res) => {
  const { message } = req.body;

  if (message.toLowerCase().includes("help") || message.toLowerCase().includes("domestic violence")) {
    await client.calls.create({
      to: "POLICE_PHONE_NUMBER", // Replace this
      from: twilioPhoneNumber,
      url: "http://demo.twilio.com/docs/voice.xml",
    });
    await client.messages.create({
      to: "EMERGENCY_CONTACT_NUMBER", // Replace this
      from: twilioPhoneNumber,
      body: "Urgent: The user needs help! Please call them immediately.",
    });

    return res.json({
      reply: "Your emergency request has been sent to the police and your emergency contacts.",
    });
  }

  if (message.toLowerCase().includes("advocate")) {
    return res.json({
      reply: "I can help you schedule a meeting with an advocate. Please provide your availability.",
    });
  }

  res.json({ reply: "I'm here to assist you. Please let me know what you need help with." });
});

// --------------------
// Socket.io
// --------------------
io.on('connection', (socket) => {
  console.log('New client connected');
  socket.on('sendMessage', (message) => {
    console.log('Message received: ', message);
    socket.emit('receiveMessage', 'Thank you for your message. We are reviewing it.');
  });
  socket.on('disconnect', () => {
    console.log('Client disconnected');
  });
});

// --------------------
// Start the server
// --------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
