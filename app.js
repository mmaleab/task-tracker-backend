require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const pool = require('./db');
const authMiddleware = require('./authMiddleware');

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;

// Automatic migration: Ensure priority column exists in tasks and archived_tasks tables
pool.query(`
  ALTER TABLE tasks 
  ADD COLUMN IF NOT EXISTS priority VARCHAR(10) DEFAULT 'medium' 
  CHECK (priority IN ('high', 'medium', 'low'));

  ALTER TABLE archived_tasks 
  ADD COLUMN IF NOT EXISTS priority VARCHAR(10) DEFAULT 'medium' 
  CHECK (priority IN ('high', 'medium', 'low'));
`).catch(err => console.log('Priority column check info:', err.message));

app.get('/', (req, res) => {
  res.send('Task Tracker API is running!');
});

// SIGNUP: create a new user account
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email`,
      [email, hashedPassword]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Something went wrong creating the account' });
  }
});

// LOGIN: check email + password, then give back a token
app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }
    const user = result.rows[0];
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

// CREATE TASK: handles empty inputs & formats date/time + priority
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

// UPDATE TASK: updates task details, completion status, and priority
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

// ARCHIVE: Move current week's tasks to archived_tasks table (including priority)
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

// DASHBOARD: Fetch archived tasks statistics grouped by week
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

// start the server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});