const pool = require('./db');

pool.query('SELECT NOW()', (err, res) => {
  if (err) {
    console.error('Connection failed:', err);
  } else {
    console.log('Connected successfully! Server time:', res.rows[0].now);
  }
  pool.end();
});