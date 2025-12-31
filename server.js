const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();

// Middleware
app.use(cors());
app.use(express.json());

// MongoDB Connection (NO deprecated options)
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/jiffy-apply')
.then(() => console.log('MongoDB connected successfully'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true
  },
  password: {
    type: String,
    required: true
  },
  firstName: {
    type: String,
    required: true
  },
  lastName: {
    type: String,
    required: true
  },
  phone: String,
  createdAt: {
    type: Date,
    default: Date.now
  },
  subscription: {
    status: {
      type: String,
      enum: ['free', 'active', 'cancelled'],
      default: 'free'
    },
    startDate: Date,
    endDate: Date,
    paymentMethod: {
      cardLast4: String,
      cardType: String,
      expiryDate: String
    }
  },
  applicationCount: {
    type: Number,
    default: 0
  },
  freeApplicationsRemaining: {
    type: Number,
    default: 50
  },
  acknowledgedFees: {
    type: Boolean,
    default: false
  },
  resume: {
    text: String,
    parsedData: {
      skills: [String],
      experience: [String],
      jobTitles: [String],
      education: [String],
      keywords: [String]
    },
    lastUpdated: Date
  }
});

// Application Schema
const applicationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  jobId: {
    type: String,
    required: true
  },
  title: {
    type: String,
    required: true
  },
  company: {
    type: String,
    required: true
  },
  location: String,
  salary: String,
  appliedDate: {
    type: Date,
    default: Date.now
  },
  considerationDate: Date,
  hiringManager: String,
  contactEmail: String,
  contactPhone: String,
  status: {
    type: String,
    enum: ['Applied', 'Under Review', 'Interview Scheduled', 'Rejected', 'Offer'],
    default: 'Applied'
  },
  source: {
    type: String,
    enum: ['Adzuna', 'USAJOBS'],
    required: true
  },
  notes: String
});

const User = mongoose.model('User', userSchema);
const Application = mongoose.model('Application', applicationSchema);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware to verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const verified = jwt.verify(token, JWT_SECRET);
    req.user = verified;
    next();
  } catch (error) {
    res.status(403).json({ error: 'Invalid token' });
  }
};

// Routes

// Register
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, firstName, lastName, phone } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ error: 'Email already registered' });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    const user = new User({
      email,
      password: hashedPassword,
      firstName,
      lastName,
      phone
    });

    await user.save();

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.status(201).json({
      message: 'User registered successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        applicationCount: user.applicationCount,
        freeApplicationsRemaining: user.freeApplicationsRemaining,
        subscription: user.subscription
      }
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(400).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, {
      expiresIn: '7d'
    });

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        applicationCount: user.applicationCount,
        freeApplicationsRemaining: user.freeApplicationsRemaining,
        subscription: user.subscription,
        acknowledgedFees: user.acknowledgedFees
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// Get user profile
app.get('/api/user/profile', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select('-password');
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    res.json(user);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Acknowledge fees
app.post('/api/user/acknowledge-fees', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    user.acknowledgedFees = true;
    await user.save();

    res.json({ message: 'Fees acknowledged', acknowledgedFees: true });
  } catch (error) {
    console.error('Acknowledge fees error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Subscribe
app.post('/api/subscription/subscribe', authenticateToken, async (req, res) => {
  try {
    const { cardNumber, cardName, expiryDate, cvv } = req.body;

    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const cardLast4 = cardNumber.slice(-4);
    const cardType = getCardType(cardNumber);

    user.subscription = {
      status: 'active',
      startDate: new Date(),
      endDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      paymentMethod: {
        cardLast4,
        cardType,
        expiryDate
      }
    };

    await user.save();

    res.json({
      message: 'Subscription activated successfully',
      subscription: user.subscription
    });
  } catch (error) {
    console.error('Subscription error:', error);
    res.status(500).json({ error: 'Server error during subscription' });
  }
});

// Get all applications for user
app.get('/api/applications', authenticateToken, async (req, res) => {
  try {
    const applications = await Application.find({ userId: req.user.userId })
      .sort({ appliedDate: -1 });
    res.json(applications);
  } catch (error) {
    console.error('Fetch applications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Create new application
app.post('/api/applications', authenticateToken, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.freeApplicationsRemaining <= 0 && user.subscription.status !== 'active') {
      return res.status(403).json({
        error: 'No applications remaining',
        message: 'Please subscribe to continue applying to jobs',
        requiresSubscription: true
      });
    }

    const application = new Application({
      userId: req.user.userId,
      ...req.body
    });

    await application.save();

    user.applicationCount += 1;
    if (user.freeApplicationsRemaining > 0) {
      user.freeApplicationsRemaining -= 1;
    }
    await user.save();

    res.status(201).json({
      message: 'Application created successfully',
      application,
      freeApplicationsRemaining: user.freeApplicationsRemaining
    });
  } catch (error) {
    console.error('Create application error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Bulk create applications
app.post('/api/applications/bulk', authenticateToken, async (req, res) => {
  try {
    const { applications } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const availableApplications = user.subscription.status === 'active' 
      ? applications.length 
      : Math.min(applications.length, user.freeApplicationsRemaining);

    if (availableApplications === 0) {
      return res.status(403).json({
        error: 'No applications remaining',
        message: 'Please subscribe to continue applying to jobs',
        requiresSubscription: true
      });
    }

    const applicationsToCreate = applications.slice(0, availableApplications).map(app => ({
      userId: req.user.userId,
      ...app
    }));

    const createdApplications = await Application.insertMany(applicationsToCreate);

    user.applicationCount += createdApplications.length;
    if (user.subscription.status !== 'active') {
      user.freeApplicationsRemaining -= createdApplications.length;
    }
    await user.save();

    res.status(201).json({
      message: `${createdApplications.length} applications created successfully`,
      applications: createdApplications,
      freeApplicationsRemaining: user.freeApplicationsRemaining,
      requiresSubscription: user.freeApplicationsRemaining <= 0 && user.subscription.status !== 'active'
    });
  } catch (error) {
    console.error('Bulk create applications error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update application status
app.patch('/api/applications/:id', authenticateToken, async (req, res) => {
  try {
    const application = await Application.findOne({
      _id: req.params.id,
      userId: req.user.userId
    });

    if (!application) {
      return res.status(404).json({ error: 'Application not found' });
    }

    Object.assign(application, req.body);
    await application.save();

    res.json({ message: 'Application updated', application });
  } catch (error) {
    console.error('Update application error:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update/Save user resume
// Update/Save user resume
app.post('/api/user/resume', authenticateToken, async (req, res) => {
  try {
    const { resumeText } = req.body;
    const user = await User.findById(req.user.userId);
    
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (!resumeText || resumeText.trim().length < 50) {
      return res.status(400).json({ error: 'Resume must be at least 50 characters' });
    }

    // Parse resume with AI
    const parsedData = await parseResumeWithAI(resumeText);
    
    // Get AI suggestions
    const suggestions = await getAISuggestions(resumeText);

    user.resume = {
      text: resumeText,
      parsedData,
      lastUpdated: new Date()
    };

    await user.save();

    res.json({
      message: 'Resume saved and analyzed successfully',
      parsedData,
      suggestions
    });
  } catch (error) {
    console.error('Resume save error:', error);
    res.status(500).json({ error: 'Server error saving resume' });
  }
});

// Get AI suggestions for resume
async function getAISuggestions(resumeText) {
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1000,
        messages: [
          {
            role: "user",
            content: `You are a professional resume advisor. Analyze this resume and provide specific, actionable suggestions to improve it for job applications. Focus on: 1) Content improvements, 2) Formatting suggestions, 3) Keywords to add, 4) Skills to highlight. Be concise and specific.

Resume:
${resumeText}

Provide your response as a structured analysis with clear sections.`
          }
        ],
      })
    });

    const data = await response.json();
    return data.content[0].text;
  } catch (error) {
    console.error('AI suggestions error:', error);
    return 'Error getting AI suggestions. Your resume has been saved.';
  }
}

// AI Resume Parsing Function
async function parseResumeWithAI(resumeText) {
  try {
    const response = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: "claude-sonnet-4-20250514",
        max_tokens: 1000,
        messages: [
          {
            role: "user",
            content: `Extract key information from this resume and return ONLY a JSON object with no additional text or markdown formatting:

{
  "skills": ["skill1", "skill2", ...],
  "experience": ["job title 1", "job title 2", ...],
  "jobTitles": ["current/recent titles"],
  "education": ["degree 1", "degree 2", ...],
  "keywords": ["keyword1", "keyword2", ...]
}

Resume:
${resumeText}

Return only the JSON object, no explanation.`
          }
        ],
      })
    });

    const data = await response.json();
    let jsonText = data.content[0].text.trim();
    
    // Remove markdown code blocks if present
    jsonText = jsonText.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
    
    const parsed = JSON.parse(jsonText);
    return parsed;
  } catch (error) {
    console.error('AI parsing error:', error);
    // Return default structure if AI fails
    return {
      skills: [],
      experience: [],
      jobTitles: [],
      education: [],
      keywords: []
    };
  }
}

// Fetch jobs from Adzuna with optional keyword filtering
app.get('/api/jobs/search', async (req, res) => {
  try {
    const fetch = (await import('node-fetch')).default;
    const { keywords } = req.query;
    
    // Build search query with keywords if provided
    let searchQuery = keywords || '';
    const url = `https://api.adzuna.com/v1/api/jobs/us/search/1?app_id=4c31e65f&app_key=2a910f6dea66fef67e15128356e2019d&results_per_page=20&what=${encodeURIComponent(searchQuery)}`;
    
    const response = await fetch(url);
    
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch jobs from Adzuna' });
    }
    
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error fetching jobs:', error);
    res.status(500).json({ error: 'Server error fetching jobs' });
  }
});

// Fetch popular jobs (NO authentication required)
app.get('/api/jobs/popular', async (req, res) => {
  try {
    const fetch = (await import('node-fetch')).default;
    const response = await fetch(
      `https://api.adzuna.com/v1/api/jobs/us/search/1?app_id=4c31e65f&app_key=2a910f6dea66fef67e15128356e2019d&results_per_page=20&sort_by=date`
    );
    
    if (!response.ok) {
      return res.status(response.status).json({ error: 'Failed to fetch jobs from Adzuna' });
    }
    
    const data = await response.json();
    res.json(data);
  } catch (error) {
    console.error('Error fetching popular jobs:', error);
    res.status(500).json({ error: 'Server error fetching jobs' });
  }
});

// Helper function to determine card type
function getCardType(cardNumber) {
  const number = cardNumber.replace(/\s/g, '');
  if (/^4/.test(number)) return 'Visa';
  if (/^5[1-5]/.test(number)) return 'Mastercard';
  if (/^3[47]/.test(number)) return 'Amex';
  if (/^6(?:011|5)/.test(number)) return 'Discover';
  return 'Unknown';
}

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
