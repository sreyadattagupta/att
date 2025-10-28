// ======================
// 📘 Dynamic QR Attendance Backend
// ======================
require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const bodyParser = require('body-parser');
const cron = require('node-cron');

const app = express();
const PORT = 3000;

// ======================
// 🔹 MIDDLEWARE
// ======================
app.use(cors());
app.use(bodyParser.json());

// ======================
// 🔹 DATABASE CONNECTION
// ======================
const MONGO_URI = 'mongodb+srv://user:1234@cluster0.hvmozek.mongodb.net/?appName=Cluster0';

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('✅ Connected to MongoDB'))
  .catch(err => console.error('❌ Failed to connect to MongoDB', err));

// ======================
// 🔹 SCHEMAS & MODELS
// ======================

// --- Teacher Schema ---
const teacherSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true },
  password: { type: String, required: true },
  tokens: [String]
});
const Teacher = mongoose.model('Teacher', teacherSchema);

// --- Student Schema ---
const studentSchema = new mongoose.Schema({
  regNumber: { type: String, required: true, unique: true },
  password: { type: String, required: true }
});
const Student = mongoose.model('Student', studentSchema);

// --- Subject Schema ---
const subjectSchema = new mongoose.Schema({
  name: { type: String, required: true },
  teacherEmail: { type: String, required: true }
});
const Subject = mongoose.model('Subject', subjectSchema);

// --- Attendance Schema ---
const attendanceSchema = new mongoose.Schema({
  regNumber: { type: String, required: true },
  subject: { type: String, required: true },
  date: { type: String, required: true },
  status: { type: String, enum: ['present', 'absent'], default: 'absent' },
  scoreChange: { type: Number, default: 0 }
});
const Attendance = mongoose.model('Attendance', attendanceSchema);

// --- QR Session Schema ---
const qrSessionSchema = new mongoose.Schema({
  subject: { type: String, required: true },
  qrId: { type: String, required: true, unique: true },
  createdAt: { type: Date, default: Date.now },
  expiresAt: { type: Date, required: true }
});
const QrSession = mongoose.model('QrSession', qrSessionSchema);

// ======================
// 🔹 HELPER FUNCTIONS
// ======================
const generateToken = teacherId =>
  jwt.sign({ id: teacherId }, process.env.JWT_SECRET || 'secretkey', {
    expiresIn: process.env.JWT_EXPIRES_IN || '1d'
  });

// --- Teacher JWT Authentication Middleware ---
const authenticate = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer '))
    return res.status(401).json({ message: 'No token provided' });

  const token = authHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'secretkey');
    const teacher = await Teacher.findById(decoded.id);
    if (!teacher || !teacher.tokens.includes(token))
      return res.status(401).json({ message: 'Invalid token' });

    req.teacher = teacher;
    req.token = token;
    next();
  } catch {
    res.status(401).json({ message: 'Invalid or expired token' });
  }
};

// ======================
// 🔹 TEACHER ROUTES
// ======================
app.post('/register', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: 'Please provide email and password.' });

    if (await Teacher.findOne({ email }))
      return res.status(400).json({ message: 'Email already in use.' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const teacher = new Teacher({ email, password: hashedPassword });
    const token = generateToken(teacher._id);
    teacher.tokens.push(token);
    await teacher.save();

    res.status(201).json({ message: 'Teacher registered', token, teacher: { email } });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const teacher = await Teacher.findOne({ email });
    if (!teacher) return res.status(401).json({ message: 'Invalid email or password' });
    const match = await bcrypt.compare(password, teacher.password);
    if (!match) return res.status(401).json({ message: 'Invalid email or password' });
    const token = generateToken(teacher._id);
    teacher.tokens.push(token);
    await teacher.save();
    res.json({ message: 'Login successful', token, teacher: { email } });
  } catch {
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/logout', authenticate, async (req, res) => {
  req.teacher.tokens = req.teacher.tokens.filter(t => t !== req.token);
  await req.teacher.save();
  res.json({ message: 'Logout successful' });
});

app.get('/subjects', authenticate, async (req, res) => {
  const subjects = await Subject.find({ teacherEmail: req.teacher.email });
  res.json({ subjects });
});

app.post('/subjects', authenticate, async (req, res) => {
  const { name } = req.body;
  if (!name) return res.status(400).json({ message: 'Subject name required' });
  const subject = await Subject.create({ name, teacherEmail: req.teacher.email });
  res.json({ message: 'Subject added', subject });
});

// ======================
// 🔹 STUDENT ROUTES
// ======================
app.post('/student/register', async (req, res) => {
  const { regNumber, password } = req.body;
  if (!regNumber || !password)
    return res.status(400).json({ message: 'Missing registration number or password' });

  if (await Student.findOne({ regNumber }))
    return res.status(400).json({ message: 'Student already exists' });

  const hashed = await bcrypt.hash(password, 10);
  await Student.create({ regNumber, password: hashed });
  res.json({ message: 'Student registered successfully' });
});

app.post('/student/login', async (req, res) => {
  const { regNumber, password } = req.body;
  const student = await Student.findOne({ regNumber });
  if (!student) return res.status(400).json({ message: 'Invalid registration number' });
  const match = await bcrypt.compare(password, student.password);
  if (!match) return res.status(400).json({ message: 'Incorrect password' });
  res.json({ message: 'Login successful', student: { regNumber } });
});

// ======================
// 🔹 ATTENDANCE ROUTES
// ======================

// Create new QR session (valid for 5 minutes)
app.post('/attendance/session', authenticate, async (req, res) => {
  const { subject } = req.body;
  if (!subject) return res.status(400).json({ message: 'Subject required' });
  const qrId = `${subject}-${Date.now()}-${Math.random().toString(36).substring(2, 8)}`;
  const expiresAt = new Date(Date.now() + 5 * 60 * 1000);
  await QrSession.create({ subject, qrId, expiresAt });
  res.json({ message: 'QR session created', qrId, expiresAt });
});

// Student scans QR to mark attendance (+1)
app.post('/attendance/mark', async (req, res) => {
  try {
    const { regNumber, subject, qrId } = req.body;
    if (!regNumber || !subject || !qrId)
      return res.status(400).json({ message: 'Missing data' });

    const session = await QrSession.findOne({ qrId });
    if (!session) return res.status(400).json({ message: 'Invalid QR' });
    if (new Date() > session.expiresAt)
      return res.status(400).json({ message: 'QR expired' });

    const date = new Date().toISOString().split('T')[0];
    let record = await Attendance.findOne({ regNumber, subject, date });

    if (record && record.status === 'present')
      return res.json({ message: 'Already marked present today' });

    if (!record)
      record = new Attendance({ regNumber, subject, date, status: 'present', scoreChange: +1 });
    else {
      record.status = 'present';
      record.scoreChange = +1;
    }

    await record.save();
    res.json({ message: 'Attendance marked (+1)', record });
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Server error' });
  }
});

// Fetch attendance for a student
app.get('/attendance/:regNumber', async (req, res) => {
  const records = await Attendance.find({ regNumber: req.params.regNumber }).sort({ date: -1 });
  res.json({ records });
});

// Manual -3 decrement (optional trigger)
app.post('/attendance/decrement', async (req, res) => {
  const { regNumber, subject } = req.body;
  const date = new Date().toISOString().split('T')[0];
  const record = await Attendance.findOne({ regNumber, subject, date });
  if (!record) {
    await Attendance.create({ regNumber, subject, date, status: 'absent', scoreChange: -3 });
    res.json({ message: 'Absent recorded (-3)' });
  } else if (record.status === 'absent') {
    res.json({ message: 'Already absent today' });
  } else {
    res.json({ message: 'Present — no penalty' });
  }
});

// ======================
// 🔹 DAILY CRON (-3 for no scan)
// ======================
cron.schedule('59 23 * * *', async () => {
  console.log('🕛 Running daily attendance decrement...');
  const students = await Student.find();
  const subjects = await Subject.find();
  const today = new Date().toISOString().split('T')[0];

  for (let student of students) {
    for (let subj of subjects) {
      const record = await Attendance.findOne({
        regNumber: student.regNumber,
        subject: subj.name,
        date: today
      });
      if (!record) {
        await Attendance.create({
          regNumber: student.regNumber,
          subject: subj.name,
          date: today,
          status: 'absent',
          scoreChange: -3
        });
      }
    }
  }
  console.log('✅ Daily decrement complete');
});

// ======================
// 🔹 START SERVER
// ======================
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));
