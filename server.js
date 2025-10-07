const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const path = require('path');

dotenv.config();

const app = express();

// Middleware - IMPORTANT: Order matters!
app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files (HTML, CSS, JS, images)
app.use(express.static(path.join(__dirname)));

// Debug middleware to log requests
app.use((req, res, next) => {
  console.log(`${req.method} ${req.url}`);
  next();
});

// MongoDB Connection
mongoose.connect(process.env.MONGODB_URI)
.then(() => console.log('MongoDB Connected Successfully'))
.catch(err => console.log('MongoDB Connection Error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  email: { type: String, required: true, unique: true, lowercase: true },
  phone: { type: String, required: true },
  gender: { type: String, enum: ['male', 'female', 'other'], required: true },
  password: { type: String, required: true },
  role: { type: String, enum: ['customer', 'provider'], default: 'customer' },
  createdAt: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// Provider Schema
const providerSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  services: [{ type: String }],
  experience: { type: Number },
  location: { type: String },
  availability: { type: String },
  rating: { type: Number, default: 0 },
  totalReviews: { type: Number, default: 0 },
  verified: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now }
});

const Provider = mongoose.model('Provider', providerSchema);

// Booking Schema
const bookingSchema = new mongoose.Schema({
  bookingId: { type: String, required: true, unique: true },
  customerId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  providerId: { type: mongoose.Schema.Types.ObjectId, ref: 'Provider', required: true },
  service: { type: String, required: true },
  date: { type: Date, required: true },
  time: { type: String, required: true },
  location: { type: String, required: true },
  amount: { type: Number, required: true },
  status: { 
    type: String, 
    enum: ['pending', 'confirmed', 'completed', 'cancelled'], 
    default: 'pending' 
  },
  createdAt: { type: Date, default: Date.now }
});

const Booking = mongoose.model('Booking', bookingSchema);

// Contact Form Schema
const contactSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true },
  phone: { type: String },
  subject: { type: String, required: true },
  message: { type: String, required: true },
  status: { type: String, enum: ['new', 'replied', 'closed'], default: 'new' },
  createdAt: { type: Date, default: Date.now }
});

const Contact = mongoose.model('Contact', contactSchema);

// Middleware to verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ message: 'No token provided' });
  }
  
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: 'Invalid token' });
    }
    req.userId = decoded.id;
    req.userRole = decoded.role;
    next();
  });
};

// ============= AUTH ROUTES =============

// User Signup
app.post('/api/auth/signup', async (req, res) => {
  try {
    console.log('Signup request received');
    console.log('Request body:', req.body);
    
    const { fullName, email, phone, gender, password } = req.body;
    
    // Validate input
    if (!fullName || !email || !phone || !gender || !password) {
      return res.status(400).json({ 
        message: 'All fields are required',
        received: { fullName, email, phone, gender, password: password ? '***' : undefined }
      });
    }
    
    if (password.length < 8) {
      return res.status(400).json({ message: 'Password must be at least 8 characters' });
    }
    
    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: 'User already exists with this email' });
    }
    
    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // Create new user
    const newUser = new User({
      fullName,
      email,
      phone,
      gender,
      password: hashedPassword
    });
    
    await newUser.save();
    
    // Generate JWT token
    const token = jwt.sign(
      { id: newUser._id, role: newUser.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: newUser._id,
        fullName: newUser.fullName,
        email: newUser.email,
        role: newUser.role
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ message: 'Email and password are required' });
    }
    
    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Check password
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }
    
    // Generate JWT token
    const token = jwt.sign(
      { id: user._id, role: user.role }, 
      process.env.JWT_SECRET, 
      { expiresIn: '7d' }
    );
    
    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        fullName: user.fullName,
        email: user.email,
        role: user.role
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get current user profile
app.get('/api/auth/me', verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password');
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ============= BOOKING ROUTES =============

// Create a new booking
app.post('/api/bookings', verifyToken, async (req, res) => {
  try {
    const { providerId, service, date, time, location, amount } = req.body;
    
    // Generate unique booking ID
    const bookingId = 'BK' + Date.now().toString().slice(-6);
    
    const booking = new Booking({
      bookingId,
      customerId: req.userId,
      providerId,
      service,
      date,
      time,
      location,
      amount,
      status: 'pending'
    });
    
    await booking.save();
    
    res.status(201).json({
      message: 'Booking created successfully',
      booking
    });
  } catch (error) {
    console.error('Booking error:', error);
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get user's bookings
app.get('/api/bookings/my-bookings', verifyToken, async (req, res) => {
  try {
    const bookings = await Booking.find({ customerId: req.userId })
      .populate('providerId')
      .sort({ createdAt: -1 });
    
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all bookings (for providers/admin)
app.get('/api/bookings', verifyToken, async (req, res) => {
  try {
    let query = {};
    
    // If user is a provider, show only their bookings
    if (req.userRole === 'provider') {
      const provider = await Provider.findOne({ userId: req.userId });
      if (provider) {
        query.providerId = provider._id;
      }
    }
    
    const bookings = await Booking.find(query)
      .populate('customerId', 'fullName email phone')
      .populate('providerId')
      .sort({ createdAt: -1 });
    
    res.json(bookings);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Update booking status
app.patch('/api/bookings/:id/status', verifyToken, async (req, res) => {
  try {
    const { status } = req.body;
    const booking = await Booking.findByIdAndUpdate(
      req.params.id,
      { status },
      { new: true }
    );
    
    if (!booking) {
      return res.status(404).json({ message: 'Booking not found' });
    }
    
    res.json({ message: 'Booking status updated', booking });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ============= PROVIDER ROUTES =============

// Register as provider
app.post('/api/providers/register', verifyToken, async (req, res) => {
  try {
    const { services, experience, location, availability } = req.body;
    
    // Check if already a provider
    const existingProvider = await Provider.findOne({ userId: req.userId });
    if (existingProvider) {
      return res.status(400).json({ message: 'Already registered as provider' });
    }
    
    // Update user role
    await User.findByIdAndUpdate(req.userId, { role: 'provider' });
    
    const provider = new Provider({
      userId: req.userId,
      services,
      experience,
      location,
      availability
    });
    
    await provider.save();
    
    res.status(201).json({
      message: 'Provider registration successful',
      provider
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all providers
app.get('/api/providers', async (req, res) => {
  try {
    const { service, location } = req.query;
    let query = { verified: true };
    
    if (service) {
      query.services = service;
    }
    
    if (location) {
      query.location = new RegExp(location, 'i');
    }
    
    const providers = await Provider.find(query)
      .populate('userId', 'fullName email phone');
    
    res.json(providers);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get provider profile
app.get('/api/providers/:id', async (req, res) => {
  try {
    const provider = await Provider.findById(req.params.id)
      .populate('userId', 'fullName email phone');
    
    if (!provider) {
      return res.status(404).json({ message: 'Provider not found' });
    }
    
    res.json(provider);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ============= CONTACT ROUTES =============

// Submit contact form
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, subject, message } = req.body;
    
    if (!name || !email || !subject || !message) {
      return res.status(400).json({ message: 'Required fields missing' });
    }
    
    const contact = new Contact({
      name,
      email,
      phone,
      subject,
      message
    });
    
    await contact.save();
    
    res.status(201).json({
      message: 'Thank you for contacting us! We will get back to you soon.',
      contact
    });
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// Get all contact submissions (admin only)
app.get('/api/contact', verifyToken, async (req, res) => {
  try {
    const contacts = await Contact.find().sort({ createdAt: -1 });
    res.json(contacts);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// ============= DASHBOARD STATS =============

// Get dashboard statistics
app.get('/api/dashboard/stats', verifyToken, async (req, res) => {
  try {
    let stats = {};
    
    if (req.userRole === 'provider') {
      const provider = await Provider.findOne({ userId: req.userId });
      
      if (!provider) {
        return res.status(404).json({ message: 'Provider profile not found' });
      }
      
      const totalBookings = await Booking.countDocuments({ providerId: provider._id });
      const pendingBookings = await Booking.countDocuments({ 
        providerId: provider._id, 
        status: 'pending' 
      });
      const completedBookings = await Booking.countDocuments({ 
        providerId: provider._id, 
        status: 'completed' 
      });
      
      const revenueData = await Booking.aggregate([
        { $match: { providerId: provider._id, status: 'completed' } },
        { $group: { _id: null, total: { $sum: '$amount' } } }
      ]);
      
      stats = {
        totalBookings,
        pendingBookings,
        completedBookings,
        totalRevenue: revenueData[0]?.total || 0,
        averageRating: provider.rating
      };
    } else {
      const totalBookings = await Booking.countDocuments({ customerId: req.userId });
      const pendingBookings = await Booking.countDocuments({ 
        customerId: req.userId, 
        status: 'pending' 
      });
      
      stats = {
        totalBookings,
        pendingBookings
      };
    }
    
    res.json(stats);
  } catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
  }
});

// API Health check route
app.get('/api', (req, res) => {
  res.json({ message: 'Suvidhaa API is running successfully!' });
});

// Serve HTML pages - This should be AFTER all API routes
app.get('*', (req, res) => {
  // Don't serve HTML for API routes
  if (req.url.startsWith('/api')) {
    return res.status(404).json({ message: 'API endpoint not found' });
  }
  
  // Serve index.html for root
  if (req.url === '/') {
    return res.sendFile(path.join(__dirname, 'index.html'));
  }
  
  // For other routes, try to serve the file
  const filePath = path.join(__dirname, req.url);
  res.sendFile(filePath, (err) => {
    if (err) {
      res.status(404).sendFile(path.join(__dirname, 'index.html'));
    }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({ message: 'Something went wrong!', error: err.message });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
