require('dotenv').config(); // load variables from .env file
const express = require('express');
const cors = require('cors'); // allows the frontend (different port) to talk to this backend
const bcrypt = require('bcrypt'); // used to hash and check passwords
const jwt = require('jsonwebtoken'); // used to create login tokens
const pool = require('./db');
const authMiddleware = require('./authMiddleware'); // checks for a valid token

const app = express();
app.use(cors()); // enable CORS for all routes
app.use(express.json()); // allows the app to read JSON sent in requests

const PORT = process.env.PORT || 3000;

app.get('/', (req, res) => {
  res.send('Task Tracker API is running!');
});

// SIGNUP: create a new user account
app.post('/signup', async (req, res) => {
  const { email, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10); // scramble password before saving

    const result = await pool.query(
      `INSERT INTO users (email, password_hash)
       VALUES ($1, $2)
       RETURNING id, email`, // never return the password
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
    // step 1: find the user by email
    const result = await pool.query(
      'SELECT * FROM users WHERE email = $1',
      [email]
    );

    // no user with that email
    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = result.rows[0];

    // step 2: check password against the saved hash
    const passwordMatch = await bcrypt.compare(password, user.password_hash);

    // wrong password (same generic error as above, on purpose)
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // step 3: create a token proving this user is logged in
    const token = jwt.sign(
      { userId: user.id, email: user.email }, // data stored inside the token
      process.env.JWT_SECRET, // secret key used to sign the token
      { expiresIn: '2h' } // token expires after 2 hours
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

// CREATE TASK: handles empty inputs & formats time (12h to 24h) for PostgreSQL
app.post('/tasks', authMiddleware, async (req, res) => {
  const { title, description, due_date, due_time } = req.body;
  const user_id = req.user.userId;

  // 1. Format date and description
  const formattedDate = due_date && due_date.trim() !== '' ? due_date : null;
  const formattedDesc = description && description.trim() !== '' ? description : null;

  // 2. Format time from 12h (e.g. "10:59 PM") to 24h (e.g. "22:59:00")
  let formattedTime = null;
  if (due_time && due_time.trim() !== '') {
    const timeRegex = /^(\d{1,2}):(\d{2})\s*(AM|PM)?$/i;
    const match = due_time.trim().match(timeRegex);

    if (match) {
      let hours = parseInt(match[1], 10);
      const minutes = match[2];
      const modifier = match[3];

      if (modifier) {
        if (modifier.toUpperCase() === 'PM' && hours < 12) hours += 12;
        if (modifier.toUpperCase() === 'AM' && hours === 12) hours = 0;
      }
      formattedTime = `${hours.toString().padStart(2, '0')}:${minutes}:00`;
    } else {
      formattedTime = due_time;
    }
  }

  try {
    const result = await pool.query(
      `INSERT INTO tasks (title, description, due_date, due_time, user_id)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [title, formattedDesc, formattedDate, formattedTime, user_id]
    );
    res.status(201).json(result.rows[0]);
  } catch (err) {
    console.error('Error creating task:', err);
    res.status(500).json({ error: 'Something went wrong creating the task' });
  }
});

// UPDATE TASK
app.put('/tasks/:id', authMiddleware, async (req, res) => {
  const { id } = req.params;
  const { title, description, due_date, due_time, is_completed } = req.body;
  const user_id = req.user.userId;

  const formattedDate = due_date && due_date.trim() !== '' ? due_date : null;
  const formattedDesc = description && description.trim() !== '' ? description : null;

  let formattedTime = null;
  if (due_time && due_time.trim() !== '') {
    const timeRegex = /^(\d{1,2}):(\d{2})\s*(AM|PM)?$/i;
    const match = due_time.trim().match(timeRegex);

    if (match) {
      let hours = parseInt(match[1], 10);
      const minutes = match[2];
      const modifier = match[3];

      if (modifier) {
        if (modifier.toUpperCase() === 'PM' && hours < 12) hours += 12;
        if (modifier.toUpperCase() === 'AM' && hours === 12) hours = 0;
      }
      formattedTime = `${hours.toString().padStart(2, '0')}:${minutes}:00`;
    } else {
      formattedTime = due_time;
    }
  }

  try {
    const result = await pool.query(
      `UPDATE tasks
       SET title = $1, description = $2, due_date = $3, due_time = $4, is_completed = $5
       WHERE id = $6 AND user_id = $7
       RETURNING *`,
      [title, formattedDesc, formattedDate, formattedTime, is_completed, id, user_id]
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

// ARCHIVE: Move current week's tasks to archived_tasks table
app.post('/tasks/archive', authMiddleware, async (req, res) => {
  const { week_start_date } = req.body; // e.g. "2026-07-19"
  const user_id = req.user.userId;

  if (!week_start_date) {
    return res.status(400).json({ error: 'week_start_date is required (YYYY-MM-DD)' });
  }

  const client = await pool.connect();

  try {
    await client.query('BEGIN');

    const archiveQuery = `
      INSERT INTO archived_tasks (title, description, due_date, due_time, is_completed, week_start_date, user_id)
      SELECT title, description, due_date, due_time, is_completed, $1, user_id
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

// start the server (must always be last)
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});