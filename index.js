const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const CryptoJS = require('crypto-js');
const nodemailer = require('nodemailer');
const multer = require('multer');
require('dotenv').config();

const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();

const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'secret';
const DATA_SECRET = process.env.DATA_SECRET || 'secret';


/* ================= CORS ================= */

app.use(
  cors({
    origin: process.env.FRONTEND_URL || '*',
    credentials: true,
  })
);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));


/* ================= MONGODB ================= */

async function connectDB() {
  if (mongoose.connection.readyState === 1) return;

  if (!process.env.MONGO_URI) {
    console.error('❌ MONGO_URI missing from environment variables');
    process.exit(1);
  }

  try {
    await mongoose.connect(process.env.MONGO_URI);
    console.log('✅ MongoDB connected');
  } catch (err) {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  }
}

connectDB(); // connect once on startup


/* ================= MULTER ================= */

const storage = multer.memoryStorage();
const upload = multer({ storage });


/* ================= MODELS ================= */

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now }
});

const User =
  mongoose.models.User ||
  mongoose.model('User', userSchema);


const beneficiarySchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  name: String,
  email: String
});

const Beneficiary =
  mongoose.models.Beneficiary ||
  mongoose.model('Beneficiary', beneficiarySchema);


const medicalSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  doctorName: String,
  prescriptions: String,
  medicalReport: String
});

const MedicalInfo =
  mongoose.models.MedicalInfo ||
  mongoose.model('MedicalInfo', medicalSchema);


const privateSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  encryptedData: String
});

const UserPrivateData =
  mongoose.models.UserPrivateData ||
  mongoose.model('UserPrivateData', privateSchema);


/* ================= AUTH MIDDLEWARE ================= */

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];

  if (!token)
    return res.status(401).json({ error: 'No token provided' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = { id: decoded.id };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
};


/* ================= EMAIL ================= */

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


/* ================= AUTH ROUTES ================= */

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });

    const existing = await User.findOne({ email });
    if (existing)
      return res.status(409).json({ error: 'Email already registered' });

    const hash = await bcrypt.hash(password, 10);

    await new User({ name, email, passwordHash: hash }).save();

    res.json({ message: 'Registered successfully' });

  } catch (err) {
    console.error('Register error:', err.message);
    res.status(500).json({ error: 'Registration failed' });
  }
});


app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'Email and password required' });

    const user = await User.findOne({ email });
    if (!user)
      return res.status(401).json({ error: 'Invalid email or password' });

    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok)
      return res.status(401).json({ error: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1d' });

    res.json({ token });

  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});

/* ================= DASHBOARD SUMMARY ================= */

app.get('/api/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;

    const [
      medicalInfoCount,
      beneficiariesCount,
      privateData
    ] = await Promise.all([
      MedicalInfo.countDocuments({ userId }),
      Beneficiary.countDocuments({ userId }),
      UserPrivateData.findOne({ userId })
    ]);

    // Decrypt private data to extract counts
    let parsed = {};
    if (privateData?.encryptedData) {
      try {
        const decrypted = CryptoJS.AES.decrypt(privateData.encryptedData, DATA_SECRET);
        parsed = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
      } catch {
        parsed = {};
      }
    }

    res.json({
      medicalInfoCount,
      beneficiariesCount,
      bankAccountsCount:              parsed.bankAccounts?.length             || 0,
      insuranceTypes:                 parsed.insurance?.length                || 0,
      personalDocsCount:              parsed.personalDocs?.length             || 0,
      investmentsSummary:             parsed.investments?.length              ? `${parsed.investments.length} Investments` : 'No Data',
      propertyCount:                  parsed.propertyInfo?.length             || 0,
      childrenPlansCount:             parsed.childrenPlans?.length            || 0,
      taxDetailsSummary:              parsed.taxDetails                       ? 'Available' : 'No Data',
      rationCardMembers:              parsed.rationCard?.members?.length      || 0,
      cibilScoreStatus:               parsed.cibilScore                       ? `Score: ${parsed.cibilScore}` : 'Unavailable',
      consolidatedPortfolioSummary:   parsed.consolidatedPortfolio            ? 'Available' : 'No Data',
    });

  } catch (err) {
    console.error('Dashboard summary error:', err.message);
    res.status(500).json({ error: 'Failed to load dashboard summary' });
  }
});

/* ================= MEDICAL ROUTES ================= */

app.post(
  '/api/medical-info',
  authMiddleware,
  upload.single('file'),
  async (req, res) => {
    try {
      const record = new MedicalInfo({
        userId: req.user.id,
        doctorName: req.body.doctorName,
        prescriptions: req.body.prescriptions,
        medicalReport: req.file?.originalname || null
      });

      await record.save();
      res.json(record);

    } catch (err) {
      console.error('Medical save error:', err.message);
      res.status(500).json({ error: 'Failed to save medical info' });
    }
  }
);


app.get('/api/medical-info', authMiddleware, async (req, res) => {
  try {
    const data = await MedicalInfo.find({ userId: req.user.id });
    res.json(data);
  } catch (err) {
    console.error('Medical fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch medical info' });
  }
});


/* ================= BENEFICIARY ROUTES ================= */

app.post('/api/beneficiaries', authMiddleware, async (req, res) => {
  try {
    const { name, email } = req.body;

    if (!name || !email)
      return res.status(400).json({ error: 'Name and email are required' });

    await new Beneficiary({ userId: req.user.id, name, email }).save();

    res.json({ ok: true });

  } catch (err) {
    console.error('Beneficiary save error:', err.message);
    res.status(500).json({ error: 'Failed to save beneficiary' });
  }
});


app.get('/api/beneficiaries', authMiddleware, async (req, res) => {
  try {
    const list = await Beneficiary.find({ userId: req.user.id });
    res.json(list);
  } catch (err) {
    console.error('Beneficiary fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch beneficiaries' });
  }
});


/* ================= USER PRIVATE DATA ================= */

app.post('/api/user-data', authMiddleware, async (req, res) => {
  try {
    const encrypted = CryptoJS.AES.encrypt(
      JSON.stringify(req.body),
      DATA_SECRET
    ).toString();

    await UserPrivateData.findOneAndUpdate(
      { userId: req.user.id },
      { encryptedData: encrypted },
      { upsert: true, new: true }
    );

    res.json({ ok: true });

  } catch (err) {
    console.error('User data save error:', err.message);
    res.status(500).json({ error: 'Failed to save private data' });
  }
});

app.get('/api/user-data', authMiddleware, async (req, res) => {
  try {
    const record = await UserPrivateData.findOne({ userId: req.user.id });

    if (!record)
      return res.json({ data: null });

    const decrypted = CryptoJS.AES.decrypt(record.encryptedData, DATA_SECRET);
    const parsed = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));

    res.json({ data: parsed });

  } catch (err) {
    console.error('User data fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch private data' });
  }
});


/* ================= AI ROUTE ================= */

const gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

app.post('/api/ai-chat', authMiddleware, async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY)
      return res.status(500).json({ error: 'Gemini API key not configured' });

    if (!req.body.message)
      return res.status(400).json({ error: 'Message is required' });

    const model = gemini.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const result = await model.generateContent(req.body.message);

    res.json({ response: result.response.text() });

  } catch (err) {
    console.error('AI chat error:', err.message);
    res.status(500).json({ error: 'AI request failed' });
  }
});


/* ================= HEALTH CHECK ================= */

app.get('/', (req, res) => {
  res.json({ status: '✅ KeepLegacy API is running' });
});


/* ================= 404 HANDLER ================= */

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});


/* ================= GLOBAL ERROR HANDLER ================= */

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err.message);
  res.status(500).json({ error: 'Something went wrong' });
});


/* ================= START SERVER ================= */

app.listen(PORT, () => {
  console.log(`🚀 KeepLegacy server running on port ${PORT}`);
});

module.exports = app;