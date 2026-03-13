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

app.use(cors({
  origin: process.env.FRONTEND_URL || '*',
  credentials: true,
}));

app.use(express.json({ limit: '20mb' }));
app.use(express.urlencoded({ extended: true, limit: '20mb' }));


/* ================= MONGODB ================= */

async function connectDB() {
  if (mongoose.connection.readyState === 1) return;
  if (!process.env.MONGO_URI) {
    console.error('❌ MONGO_URI missing');
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

connectDB();


/* ================= MULTER ================= */

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });


/* ================= MODELS ================= */

const userSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  passwordHash: String,
  createdAt: { type: Date, default: Date.now }
});
const User = mongoose.models.User || mongoose.model('User', userSchema);

const beneficiarySchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  name: String,
  relation: String,
  contact: String,
  email: String
});
const Beneficiary = mongoose.models.Beneficiary || mongoose.model('Beneficiary', beneficiarySchema);

const medicalSchema = new mongoose.Schema({
  userId: mongoose.Schema.Types.ObjectId,
  doctorName: String,
  prescriptions: String,
  medicalReport: String
});
const MedicalInfo = mongoose.models.MedicalInfo || mongoose.model('MedicalInfo', medicalSchema);

const privateSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, unique: true },
  encryptedData: String
});
const UserPrivateData = mongoose.models.UserPrivateData || mongoose.model('UserPrivateData', privateSchema);

// ✅ FIXED: defaults are null so we know if user has actually set a timer
const inactivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, unique: true },
  inactivityDays: { type: Number, default: null },
  inactivityMinutes: { type: Number, default: null },
  lastSeen: { type: Date, default: Date.now },
  emailSent: { type: Boolean, default: false }
});
const InactivitySetting = mongoose.models.InactivitySetting || mongoose.model('InactivitySetting', inactivitySchema);

const fileSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  name: String,
  type: String,
  size: Number,
  data: String,
  uploadedAt: { type: Date, default: Date.now }
});
const UserFile = mongoose.models.UserFile || mongoose.model('UserFile', fileSchema);

const pageActivitySchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, required: true },
  userName: String,
  userEmail: String,
  page: String,
  lastUpdated: { type: Date, default: Date.now }
});
const PageActivity = mongoose.models.PageActivity || mongoose.model('PageActivity', pageActivitySchema);


/* ================= AUTH MIDDLEWARE ================= */

const authMiddleware = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token provided' });
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
  host: 'smtp.gmail.com',
  port: 465,
  secure: true, // ✅ use SSL instead of TLS
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});


/* ================= HELPER: Track Page Activity ================= */

const trackPage = async (userId, page) => {
  try {
    const user = await User.findById(userId).select('name email');
    await PageActivity.findOneAndUpdate(
      { userId, page },
      { userId, userName: user?.name, userEmail: user?.email, page, lastUpdated: new Date() },
      { upsert: true, new: true }
    );
  } catch (err) {
    console.error('Page tracking error:', err.message);
  }
};


/* ================= AUTH ROUTES ================= */

app.post('/api/auth/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    if (!name || !email || !password)
      return res.status(400).json({ error: 'All fields are required' });
    const existing = await User.findOne({ email });
    if (existing) return res.status(409).json({ error: 'Email already registered' });
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
    if (!user) return res.status(401).json({ error: 'Invalid email or password' });
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid email or password' });
    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '7d' });

    // ✅ Only update lastSeen — do NOT overwrite inactivityMinutes on login
    await InactivitySetting.findOneAndUpdate(
      { userId: user._id },
      { lastSeen: new Date(), emailSent: false },
      { upsert: true }
    );

    res.json({ token });
  } catch (err) {
    console.error('Login error:', err.message);
    res.status(500).json({ error: 'Login failed' });
  }
});


app.get('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json(user);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch profile' });
  }
});


app.put('/api/auth/profile', authMiddleware, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Name is required' });
    await User.findByIdAndUpdate(req.user.id, { name });
    res.json({ message: 'Profile updated' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to update profile' });
  }
});


app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: 'Both passwords required' });
    const user = await User.findById(req.user.id);
    const ok = await bcrypt.compare(currentPassword, user.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Current password is incorrect' });
    const hash = await bcrypt.hash(newPassword, 10);
    await User.findByIdAndUpdate(req.user.id, { passwordHash: hash });
    res.json({ message: 'Password changed successfully' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to change password' });
  }
});


app.delete('/api/auth/delete-account', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await Promise.all([
      User.findByIdAndDelete(userId),
      Beneficiary.deleteMany({ userId }),
      MedicalInfo.deleteMany({ userId }),
      UserPrivateData.deleteOne({ userId }),
      InactivitySetting.deleteOne({ userId }),
      UserFile.deleteMany({ userId }),
      PageActivity.deleteMany({ userId }),
    ]);
    res.json({ message: 'Account deleted' });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete account' });
  }
});


/* ================= DASHBOARD SUMMARY ================= */

app.get('/api/dashboard/summary', authMiddleware, async (req, res) => {
  try {
    const userId = req.user.id;
    await trackPage(userId, 'Dashboard');
    const [medicalInfoCount, beneficiariesCount, privateData] = await Promise.all([
      MedicalInfo.countDocuments({ userId }),
      Beneficiary.countDocuments({ userId }),
      UserPrivateData.findOne({ userId })
    ]);
    let parsed = {};
    if (privateData?.encryptedData) {
      try {
        const decrypted = CryptoJS.AES.decrypt(privateData.encryptedData, DATA_SECRET);
        parsed = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
      } catch { parsed = {}; }
    }
    res.json({
      medicalInfoCount,
      beneficiariesCount,
      bankAccountsCount:            parsed.bankAccounts?.length          || 0,
      insuranceTypes:               parsed.insurance?.length             || 0,
      personalDocsCount:            parsed.personalDocs?.length          || 0,
      investmentsSummary:           parsed.investments?.length           ? `${parsed.investments.length} Investments` : 'No Data',
      propertyCount:                parsed.propertyInfo?.length          || 0,
      childrenPlansCount:           parsed.childrenPlans?.length         || 0,
      taxDetailsSummary:            parsed.taxDetails?.length            ? 'Available' : 'No Data',
      rationCardMembers:            parsed.rationCard?.familyMembers     || 0,
      cibilScoreStatus:             parsed.cibilScore?.score             ? `Score: ${parsed.cibilScore.score}` : 'Unavailable',
      consolidatedPortfolioSummary: parsed.consolidatedPortfolio         ? 'Available' : 'No Data',
    });
  } catch (err) {
    console.error('Dashboard summary error:', err.message);
    res.status(500).json({ error: 'Failed to load dashboard summary' });
  }
});


/* ================= MEDICAL ROUTES ================= */

app.post('/api/medical-info', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    await trackPage(req.user.id, 'MedicalInfo');
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
});

app.get('/api/medical-info', authMiddleware, async (req, res) => {
  try {
    const data = await MedicalInfo.find({ userId: req.user.id });
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch medical info' });
  }
});

app.put('/api/medical-info/:id', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    const update = {
      doctorName: req.body.doctorName,
      prescriptions: req.body.prescriptions,
    };
    if (req.file) update.medicalReport = req.file.originalname;
    const updated = await MedicalInfo.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      update,
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Record not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update medical info' });
  }
});

app.delete('/api/medical-info/:id', authMiddleware, async (req, res) => {
  try {
    await MedicalInfo.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete medical info' });
  }
});


/* ================= BENEFICIARY ROUTES ================= */

app.post('/api/beneficiaries', authMiddleware, async (req, res) => {
  try {
    await trackPage(req.user.id, 'Beneficiaries');
    const { name, relation, contact, email } = req.body;
    if (!name || !relation || !contact)
      return res.status(400).json({ error: 'Name, relation and contact are required' });
    await new Beneficiary({ userId: req.user.id, name, relation, contact, email }).save();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save beneficiary' });
  }
});

app.get('/api/beneficiaries', authMiddleware, async (req, res) => {
  try {
    const list = await Beneficiary.find({ userId: req.user.id });
    res.json(list);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch beneficiaries' });
  }
});

app.put('/api/beneficiaries/:id', authMiddleware, async (req, res) => {
  try {
    const { name, relation, contact, email } = req.body;
    const updated = await Beneficiary.findOneAndUpdate(
      { _id: req.params.id, userId: req.user.id },
      { name, relation, contact, email },
      { new: true }
    );
    if (!updated) return res.status(404).json({ error: 'Not found' });
    res.json(updated);
  } catch (err) {
    res.status(500).json({ error: 'Failed to update beneficiary' });
  }
});

app.delete('/api/beneficiaries/:id', authMiddleware, async (req, res) => {
  try {
    await Beneficiary.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete beneficiary' });
  }
});


/* ================= USER PRIVATE DATA ================= */

app.post('/api/user-data', authMiddleware, async (req, res) => {
  try {
    const pageKey = Object.keys(req.body)[0];
    const pageMap = {
      bankAccounts: 'BankAccounts', insurance: 'Insurance', investments: 'Investments',
      propertyInfo: 'PropertyInfo', personalDocs: 'PersonalDocs', childrenPlans: 'ChildrenPlans',
      taxDetails: 'TaxDetails', rationCard: 'RationCard', cibilScore: 'CIBILScore',
      consolidatedPortfolio: 'ConsolidatedPortfolio'
    };
    if (pageKey && pageMap[pageKey]) await trackPage(req.user.id, pageMap[pageKey]);

    const existing = await UserPrivateData.findOne({ userId: req.user.id });
    let existingParsed = {};
    if (existing?.encryptedData) {
      try {
        const dec = CryptoJS.AES.decrypt(existing.encryptedData, DATA_SECRET);
        existingParsed = JSON.parse(dec.toString(CryptoJS.enc.Utf8));
      } catch { existingParsed = {}; }
    }

    const merged = { ...existingParsed, ...req.body };
    const encrypted = CryptoJS.AES.encrypt(JSON.stringify(merged), DATA_SECRET).toString();

    await UserPrivateData.findOneAndUpdate(
      { userId: req.user.id },
      { encryptedData: encrypted },
      { upsert: true, new: true }
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('User data save error:', err.message);
    res.status(500).json({ error: 'Failed to save data' });
  }
});

app.get('/api/user-data', authMiddleware, async (req, res) => {
  try {
    const record = await UserPrivateData.findOne({ userId: req.user.id });
    if (!record) return res.json({ data: null });
    const decrypted = CryptoJS.AES.decrypt(record.encryptedData, DATA_SECRET);
    const parsed = JSON.parse(decrypted.toString(CryptoJS.enc.Utf8));
    res.json({ data: parsed });
  } catch (err) {
    console.error('User data fetch error:', err.message);
    res.status(500).json({ error: 'Failed to fetch data' });
  }
});


/* ================= MY FILES ================= */

app.post('/api/my-files', authMiddleware, upload.single('file'), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
    await trackPage(req.user.id, 'MyFiles');
    const base64 = req.file.buffer.toString('base64');
    const newFile = new UserFile({
      userId: req.user.id,
      name: req.file.originalname,
      type: req.file.mimetype,
      size: req.file.size,
      data: base64
    });
    await newFile.save();
    res.json({ ok: true, file: { _id: newFile._id, name: newFile.name, type: newFile.type, size: newFile.size, uploadedAt: newFile.uploadedAt } });
  } catch (err) {
    console.error('File upload error:', err.message);
    res.status(500).json({ error: 'Failed to upload file' });
  }
});

app.get('/api/my-files', authMiddleware, async (req, res) => {
  try {
    const files = await UserFile.find({ userId: req.user.id }).select('-data');
    res.json(files);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch files' });
  }
});

app.get('/api/my-files/:id', authMiddleware, async (req, res) => {
  try {
    const file = await UserFile.findOne({ _id: req.params.id, userId: req.user.id });
    if (!file) return res.status(404).json({ error: 'File not found' });
    const buffer = Buffer.from(file.data, 'base64');
    res.set('Content-Type', file.type);
    res.set('Content-Disposition', `inline; filename="${file.name}"`);
    res.send(buffer);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch file' });
  }
});

app.delete('/api/my-files/:id', authMiddleware, async (req, res) => {
  try {
    await UserFile.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to delete file' });
  }
});


/* ================= INACTIVITY SETTINGS ================= */

app.post('/api/inactivity-settings', authMiddleware, async (req, res) => {
  try {
    let totalMinutes = req.body.inactivityMinutes;
    if (!totalMinutes && req.body.inactivityDays) {
      totalMinutes = req.body.inactivityDays * 24 * 60;
    }
    if (!totalMinutes || totalMinutes < 1)
      return res.status(400).json({ error: 'Minimum timer is 1 minute' });

    await InactivitySetting.findOneAndUpdate(
      { userId: req.user.id },
      {
        inactivityDays: Math.ceil(totalMinutes / 1440),
        inactivityMinutes: totalMinutes,
        lastSeen: new Date(),
        emailSent: false
      },
      { upsert: true, new: true }
    );
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Failed to save inactivity settings' });
  }
});

// ✅ FIXED: returns null when user hasn't set a timer yet
app.get('/api/inactivity-settings', authMiddleware, async (req, res) => {
  try {
    const setting = await InactivitySetting.findOne({ userId: req.user.id });
    // ✅ If no setting or inactivityMinutes is null — user hasn't set timer
    if (!setting || setting.inactivityMinutes === null) {
      return res.json({ inactivityDays: null, inactivityMinutes: null });
    }
    res.json(setting);
  } catch (err) {
    res.status(500).json({ error: 'Failed to fetch inactivity settings' });
  }
});

app.post('/api/inactivity-settings/trigger-email', authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    const beneficiaries = await Beneficiary.find({ userId: req.user.id, email: { $exists: true, $ne: '' } });

    if (!beneficiaries.length)
      return res.json({ ok: true, message: 'No beneficiaries with email' });

    const emailList = beneficiaries.map(b => b.email);

    await transporter.sendMail({
      from: `"KeepLegacy" <${process.env.EMAIL_USER}>`,
      to: emailList.join(','),
      subject: `Inactivity Alert: ${user.name || 'Your loved one'} may need your attention`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:auto;padding:30px;background:#f9fafb;border-radius:12px;">
          <div style="background:#1164e8;padding:20px;border-radius:8px;text-align:center;margin-bottom:24px;">
            <h1 style="color:white;margin:0;">KeepLegacy</h1>
          </div>
          <h2 style="color:#1164e8;">Inactivity Alert</h2>
          <p>Hello,</p>
          <p><strong>${user.name || 'A KeepLegacy user'}</strong> set an inactivity timer and it has now expired.</p>
          <p>This means they have not logged into KeepLegacy for the duration they set. Please reach out to check on them.</p>
          <div style="background:#fff3cd;border:1px solid #ffc107;padding:15px;border-radius:8px;margin:20px 0;">
            <p style="margin:0;"><strong>⚠️ Note:</strong> If ${user.name || 'they'} is safe, they can log back into KeepLegacy to reset this timer.</p>
          </div>
          <p style="color:#666;font-size:0.9rem;">This is an automated message from KeepLegacy.</p>
        </div>
      `
    });

    await InactivitySetting.findOneAndUpdate({ userId: req.user.id }, { emailSent: true });
    res.json({ ok: true });
  } catch (err) {
    console.error('Trigger email error:', err.message);
    res.status(500).json({ error: 'Failed to send email' });
  }
});


/* ================= INACTIVITY CHECKER (runs every 24h) ================= */

const checkInactivity = async () => {
  try {
    console.log('🔍 Running inactivity check...');
    // ✅ Only check users who have actually set a timer (inactivityMinutes not null)
    const allSettings = await InactivitySetting.find({
      emailSent: false,
      inactivityMinutes: { $ne: null, $gt: 0 }
    });

    for (const setting of allSettings) {
      const diffMinutes = Math.floor((new Date() - new Date(setting.lastSeen)) / (1000 * 60));
      const thresholdMinutes = setting.inactivityMinutes;

      if (diffMinutes >= thresholdMinutes) {
        const user = await User.findById(setting.userId);
        if (!user) continue;

        const beneficiaries = await Beneficiary.find({ userId: setting.userId });
        if (beneficiaries.length === 0) continue;

        for (const b of beneficiaries) {
          if (!b.email) continue;
          await transporter.sendMail({
            from: `"KeepLegacy" <${process.env.EMAIL_USER}>`,
            to: b.email,
            subject: `Important: ${user.name} has been inactive on KeepLegacy`,
            html: `
              <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;padding:30px;background:#f9fafb;border-radius:12px;">
                <div style="background:#1164e8;padding:20px;border-radius:8px;text-align:center;margin-bottom:24px;">
                  <h1 style="color:white;margin:0;">KeepLegacy</h1>
                </div>
                <h2 style="color:#1164e8;">Inactivity Alert</h2>
                <p>Dear <strong>${b.name}</strong>,</p>
                <p><strong>${user.name}</strong> has been inactive on KeepLegacy for <strong>${Math.floor(diffMinutes / 60 / 24)} days</strong>.</p>
                <p>As a trusted beneficiary, we kindly request that you check on them.</p>
                <div style="background:#fff3cd;border:1px solid #ffc107;padding:15px;border-radius:8px;margin:20px 0;">
                  <p style="margin:0;"><strong>⚠️ Note:</strong> If ${user.name} is safe, they can log back into KeepLegacy to reset this timer.</p>
                </div>
                <p style="color:#666;font-size:0.9rem;">This is an automated message from KeepLegacy.</p>
              </div>
            `
          });
          console.log(`✅ Email sent to: ${b.email}`);
        }

        await InactivitySetting.findByIdAndUpdate(setting._id, { emailSent: true });
      }
    }
  } catch (err) {
    console.error('❌ Inactivity check error:', err.message);
  }
};

setInterval(checkInactivity, 24 * 60 * 60 * 1000);
setTimeout(checkInactivity, 5000);


/* ================= AI ROUTE ================= */

const gemini = new GoogleGenerativeAI(process.env.GEMINI_API_KEY || '');

app.post('/api/ai-chat', authMiddleware, async (req, res) => {
  try {
    if (!process.env.GEMINI_API_KEY)
      return res.status(500).json({ error: 'Gemini API key not configured' });
    if (!req.body.message)
      return res.status(400).json({ error: 'Message is required' });
    const model = gemini.getGenerativeModel({ model: 'gemini-2.0-flash' });
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

// ✅ TEMPORARY: test email route — remove after testing
app.get('/api/test-email', async (req, res) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: process.env.EMAIL_USER,
      subject: 'KeepLegacy Email Test',
      text: 'If you see this, email is working!'
    });
    res.json({ ok: true, message: '✅ Email sent! Check your inbox.' });
  } catch (err) {
    res.json({ ok: false, error: err.message });
  }
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