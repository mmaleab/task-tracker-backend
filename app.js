require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { Resend } = require('resend');
const pool = require('./db');
const authMiddleware = require('./authMiddleware');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// إعداد خدمة إرسال الإيميلات عبر Resend (بديل عن Nodemailer/SMTP)
const resend = new Resend(process.env.RESEND_API_KEY);
// إيميل الإرسال الافتراضي من Resend (يعمل بدون توثيق دومين خاص)
const EMAIL_FROM = process.env.EMAIL_FROM || 'onboarding@resend.dev';

// Automatic migration: Ensure priority and verification columns exist in tables
pool.query(`
  ALTER TABLE tasks 
  ADD COLUMN IF NOT EXISTS priority VARCHAR(10) DEFAULT 'medium' 
  CHECK (priority IN ('high', 'medium', 'low'));

  ALTER TABLE archived_tasks 
  ADD COLUMN IF NOT EXISTS priority VARCHAR(10) DEFAULT 'medium' 
  CHECK (priority IN ('high', 'medium', 'low'));

  ALTER TABLE users 
  ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT false,
  ADD COLUMN IF NOT EXISTS verification_code VARCHAR(6),
  ADD COLUMN IF NOT EXISTS verification_code_expires TIMESTAMP,
  ADD COLUMN IF NOT EXISTS reset_password_token VARCHAR(100),
  ADD COLUMN IF NOT EXISTS reset_password_expires TIMESTAMP;
`).catch(err => console.log('Migration check info:', err.message));

app.get('/', (req, res) => {
  res.send('Task Tracker API is running!');
});

// ==========================================
// AUTHENTICATION & SECURITY ROUTES
// ==========================================

// SIGNUP: create a new user account and send verification code
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  let insertedUserId = null; // نتتبع الـ id لو احتجنا نحذفه لاحقاً

  try {
    const existingUser = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'البريد الإلكتروني مستخدم مسبقاً' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationCode = Math.floor(100000 + Math.random() * 900000).toString();
    const codeExpires = new Date(Date.now() + 10 * 60 * 1000); // صالح لمدة 10 دقائق

    const result = await pool.query(
      `INSERT INTO users (email, password_hash, is_verified, verification_code, verification_code_expires) 
       VALUES ($1, $2, false, $3, $4) RETURNING id, email`,
      [email, hashedPassword, verificationCode, codeExpires]
    );

    insertedUserId = result.rows[0].id;

    // محاولة إرسال الإيميل عبر Resend، لو فشلت نتراجع (rollback)
    try {
      const { error: resendError } = await resend.emails.send({
        from: EMAIL_FROM,
        to: email,
        subject: 'رمز التحقق لحسابك في Task Tracker',
        html: `<p>رمز التحقق الخاص بك هو: <strong>${verificationCode}</strong></p><p>هذا الرمز صالح لمدة 10 دقائق.</p>`
      });

      if (resendError) {
        throw new Error(resendError.message || 'Resend API error');
      }
    } catch (mailErr) {
      console.error('Failed to send verification email:', mailErr.message);

      // Rollback: نحذف المستخدم اللي انضاف عشان الإيميل ما يبقى محجوز بدون داعي
      await pool.query('DELETE FROM users WHERE id = $1', [insertedUserId]);

      return res.status(500).json({
        error: 'تعذر إرسال رمز التحقق إلى بريدك الإلكتروني. تأكد من صحة البريد وحاول مرة أخرى.'
      });
    }

    res.status(201).json({ 
      message: 'تم إنشاء الحساب بنجاح. يرجى التحقق من بريدك الإلكتروني لإدخال رمز التفعيل.',
      user: result.rows[0] 
    });
  } catch (err) {
    console.error(err);

    // في حال حصل خطأ بعد الإدراج ولم يُلتقط بالـ catch الداخلي، نتأكد من التنظيف أيضاً
    if (insertedUserId) {
      try {
        await pool.query('DELETE FROM users WHERE id = $1', [insertedUserId]);
      } catch (cleanupErr) {
        console.error('Cleanup failed:', cleanupErr.message);
      }
    }

    res.status(500).json({ error: 'حدث خطأ أثناء إنشاء الحساب' });
  }
});

// VERIFY EMAIL: check the code sent to user's email
app.post('/verify-email', async (req, res) => {
  const { email, code } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'المستخدم غير موجود' });
    }

    const user = userResult.rows[0];

    if (user.is_verified) {
      return res.status(400).json({ error: 'الحساب مفعل مسبقاً' });
    }

    if (user.verification_code !== code || new Date() > new Date(user.verification_code_expires)) {
      return res.status(400).json({ error: 'رمز التحقق غير صحيح أو انتهت صلاحيته' });
    }

    await pool.query(
      'UPDATE users SET is_verified = true, verification_code = NULL, verification_code_expires = NULL WHERE email = $1',
      [email]
    );

    res.status(200).json({ message: 'تم تفعيل الحساب بنجاح!' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حدث خطأ في الخادم أثناء التحقق' });
  }
});

// LOGIN: check email + password + verification status, then give back a token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = result.rows[0];

    if (!user.is_verified) {
      return res.status(403).json({ error: 'الحساب غير مفعل. يرجى التحقق من بريدك الإلكتروني لتفعيل الحساب.' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '2h' }
    );
    res.json({ message: 'Login successful', token });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong logging in' });
  }
});

// FORGOT PASSWORD: generate reset token and send email
app.post('/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'البريد الإلكتروني غير مسجل معنا' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const tokenExpires = new Date(Date.now() + 15 * 60 * 1000); // صالح لـ 15 دقيقة

    await pool.query(
      'UPDATE users SET reset_password_token = $1, reset_password_expires = $2 WHERE email = $3',
      [resetToken, tokenExpires, email]
    );

    const resetLink = `http://localhost:3000/reset-password.html?token=${resetToken}&email=${email}`;

    const { error: resendError } = await resend.emails.send({
      from: EMAIL_FROM,
      to: email,
      subject: 'طلب استعادة كلمة المرور',
      html: `<p>لقد طلبت إعادة تعيين كلمة المرور لحسابك. استخدم هذا الرابط للمتابعة:</p><p><a href="${resetLink}">${resetLink}</a></p><p>الرابط صالح لمدة 15 دقيقة.</p>`
    });

    if (resendError) {
      console.error('Failed to send reset email:', resendError.message);
      return res.status(500).json({ error: 'تعذر إرسال رابط استعادة كلمة المرور. حاول مرة أخرى.' });
    }

    res.status(200).json({ message: 'تم إرسال رابط استعادة كلمة المرور إلى بريدك الإلكتروني.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حدث خطأ أثناء معالجة طلب استعادة كلمة المرور' });
  }
});

// RESET PASSWORD: update password using token
app.post('/reset-password', async (req, res) => {
  const { email, token, newPassword } = req.body;
  try {
    const userResult = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (userResult.rows.length === 0) {
      return res.status(400).json({ error: 'بيانات غير صالحة' });
    }

    const user = userResult.rows[0];

    if (user.reset_password_token !== token || new Date() > new Date(user.reset_password_expires)) {
      return res.status(400).json({ error: 'رابط إعادة التعيين غير صالح أو انتهت صلاحيته' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);

    await pool.query(
      'UPDATE users SET password_hash = $1, reset_password_token = NULL, reset_password_expires = NULL WHERE email = $2',
      [hashedNewPassword, email]
    );

    res.status(200).json({ message: 'تم تحديث كلمة المرور بنجاح! يمكنك تسجيل الدخول الآن.' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'حدث خطأ أثناء تحديث كلمة المرور' });
  }
});

// ==========================================
// TASKS ROUTES
// ==========================================

// GET TASKS: fetch tasks only for the logged-in user
app.get('/tasks', authMiddleware, async (req, res) => {
  const user_id = req.user.userId;
  try {
    const result = await pool.query('SELECT * FROM tasks WHERE user_id = $1 ORDER BY id DESC', [user_id]);
    res.json(result.rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong fetching tasks' });
  }
});

// Helper: Format MM/DD/YYYY to YYYY-MM-DD
const parseToISODate = (dateStr) => {
  if (!dateStr || dateStr.trim() === '') return null;
  const cleanDate = dateStr.trim();
  const parts = cleanDate.split('/');
  if (parts.length === 3) {
    const month = parts[0].padStart(2, '0');
    const day = parts[1].padStart(2, '0');
    const year = parts[2];
    return `${year}-${month}-${day}`;
  }
  const parsed = new Date(cleanDate);
  if (!isNaN(parsed.getTime())) {
    return parsed.toISOString().split('T')[0];
  }
  return cleanDate;
};

// Helper: Format 12h/24h time to HH:MM:SS
const parseTo24HourTime = (timeStr) => {
  if (!timeStr || timeStr.trim() === '') return null;
  const cleanTime = timeStr.trim();
  const timeRegex = /^(\d{1,2}):(\d{2})\s*(AM|PM)?$/i;
  const match = cleanTime.match(timeRegex);

  if (match) {
    let hours = parseInt(match[1], 10);
    const minutes = match[2];
    const modifier = match[3];

    if (modifier) {
      if (modifier.toUpperCase() === 'PM' && hours < 12) hours += 12;
      if (modifier.toUpperCase() === 'AM' && hours === 12) hours = 0;
    }
    return `${hours.toString().padStart(2, '0')}:${minutes}:00`;
  }
  return cleanTime;
};

// CREATE TASK
app.post('/tasks', authMiddleware, async (req, res) => {
  const { title, description, due_date, due_time, priority } = req.body;
  const user_id = req.user.userId;

  const formattedDate = parseToISODate(due_date);
  const formattedTime = parseTo24HourTime(due_time);
  const formattedDesc = description && description.trim() !== '' ? description : null;
  const taskPriority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';

  try {
    const result = await pool.query(
      `INSERT INTO tasks (title, description, due_date, due_time, priority, user_id, is_completed)
       VALUES ($1, $2, $3, $4, $5, $6, false)
       RETURNING *`,
      [title, formattedDesc, formattedDate, formattedTime, taskPriority, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating task:', err);
    res.status(500).json({ error: 'Something went wrong creating the task', detail: err.message });
  }
});

// UPDATE TASK
app.put('/tasks/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, due_date, due_time, is_completed, priority } = req.body;
  const user_id = req.user.userId;

  const formattedDate = parseToISODate(due_date);
  const formattedTime = parseTo24HourTime(due_time);
  const formattedDesc = description && description.trim() !== '' ? description : null;
  const completedStatus = is_completed === true || is_completed === 'true';
  const taskPriority = ['high', 'medium', 'low'].includes(priority) ? priority : 'medium';

  try {
    const result = await pool.query(
      `UPDATE tasks
       SET title = $1, description = $2, due_date = $3, due_time = $4, is_completed = $5, priority = $6
       WHERE id = $7 AND user_id = $8
       RETURNING *`,
      [title, formattedDesc, formattedDate, formattedTime, completedStatus, taskPriority, id, user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong updating the task' });
  }
});

// DELETE TASK
app.delete('/tasks/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const user_id = req.user.userId;

  try {
    const result = await pool.query(
      'DELETE FROM tasks WHERE id = $1 AND user_id = $2 RETURNING *',
      [id, user_id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json({ message: 'Task deleted successfully', task: result.rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong deleting the task' });
  }
});

// ARCHIVE TASKS
app.post('/tasks/archive', authMiddleware, async (req, res) => {
  const { week_start_date } = req.body;
  const user_id = req.user.userId;

  if (!week_start_date) {
    return res.status(400).json({ error: 'week_start_date is required (YYYY-MM-DD)' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const archiveQuery = `
      INSERT INTO archived_tasks (title, description, due_date, due_time, is_completed, priority, week_start_date, user_id)
      SELECT title, description, due_date, due_time, is_completed, priority, $1, user_id
      FROM tasks
      WHERE user_id = $2;
    `;
    await client.query(archiveQuery, [week_start_date, user_id]);

    const deleteQuery = `DELETE FROM tasks WHERE user_id = $1;`;
    await client.query(deleteQuery, [user_id]);

    await client.query('COMMIT');

    res.json({ message: 'Tasks archived successfully for the week!' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error(err);
    res.status(500).json({ error: 'Something went wrong archiving tasks' });
  } finally {
    client.release();
  }
});

// ==========================================
// DASHBOARD ROUTES
// ==========================================

app.get('/dashboard/summary', authMiddleware, async (req, res) => {
  const user_id = req.user.userId;

  try {
    const query = `
      SELECT 
        week_start_date,
        COUNT(*) AS total_tasks,
        COUNT(*) FILTER (WHERE is_completed = true) AS completed_tasks,
        COUNT(*) FILTER (WHERE is_completed = false) AS pending_tasks,
        ROUND(
          (COUNT(*) FILTER (WHERE is_completed = true)::DECIMAL / COUNT(*)) * 100, 2
        ) AS completion_rate
      FROM archived_tasks
      WHERE user_id = $1
      GROUP BY week_start_date
      ORDER BY week_start_date DESC;
    `;

    const result = await pool.query(query, [user_id]);

    res.json({
      summary: result.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong fetching dashboard metrics' });
  }
});

app.get('/dashboard/live', authMiddleware, async (req, res) => {
  const user_id = req.user.userId;

  try {
    const statsQuery = `
      SELECT 
        COUNT(*) AS total_active,
        COUNT(*) FILTER (WHERE is_completed = true) AS completed_active,
        COUNT(*) FILTER (WHERE is_completed = false) AS pending_active,
        COUNT(*) FILTER (WHERE priority = 'high' AND is_completed = false) AS high_priority_pending,
        COUNT(*) FILTER (
          WHERE is_completed = false AND (
            due_date < CURRENT_DATE OR 
            (due_date = CURRENT_DATE AND due_time IS NOT NULL AND due_time < CURRENT_TIME)
          )
        ) AS overdue_active
      FROM tasks
      WHERE user_id = $1;
    `;

    const overdueTasksQuery = `
      SELECT id, title, description, due_date, due_time, priority 
      FROM tasks 
      WHERE user_id = $1 AND is_completed = false AND (
        due_date < CURRENT_DATE OR 
        (due_date = CURRENT_DATE AND due_time IS NOT NULL AND due_time < CURRENT_TIME)
      )
      ORDER BY due_date ASC, due_time ASC;
    `;

    const statsResult = await pool.query(statsQuery, [user_id]);
    const overdueResult = await pool.query(overdueTasksQuery, [user_id]);

    res.json({
      stats: statsResult.rows[0],
      overdueTasks: overdueResult.rows
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong fetching live dashboard metrics' });
  }
});

// start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
