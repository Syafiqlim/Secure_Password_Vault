/************************************************
 * 1 Day , 1 challenge , until urgh... I get gf?*
 * by Syafiqlim                                 *
 * date : 24th January 2024                     *
 *                  Day 17 :                    *
 * Secure Password Vault (API)                  *
 * (Encryption using AES-128-ECB)               *
 ************************************************
 */

const express = require('express');
const mysql = require('mysql2/promise');
const crypto = require('crypto');

const app = express();
const port = 3000;

app.use(express.json());

const dbConfig = {
  host: 'localhost',
  user: 'root',
  password: '',
  database: '1day_1challenge_day17'
};

async function connectToDatabase() {
  return await mysql.createConnection(dbConfig);
}

app.post('/savePassword', async (req, res) => {
  try {
    const { app, username, password } = req.body;

    // Establish the connection
    const dbConnection = await connectToDatabase();

    // Generate AES key
    const encryptionKey = crypto.randomBytes(16).toString('hex');

    // Encrypt the password using AES-128-ECB
    const cipher = crypto.createCipheriv('aes-128-ecb', Buffer.from(encryptionKey, 'hex'), Buffer.alloc(0));
    let encryptedPassword = cipher.update(password, 'utf-8', 'hex');
    encryptedPassword += cipher.final('hex');

    // Save the encrypted password to the database
    const insertQuery = `INSERT INTO User (app, username, password) VALUES (?, ?, ?)`;
    const values = [app, username, encryptedPassword];

    // Use 'execute' on 'dbConnection' directly for promises
    const [result] = await dbConnection.execute(insertQuery, values);

    res.json({ encryptionKey });
  } catch (err) {
    console.error('Error saving password to database: ', err);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/getPassword', async (req, res) => {
    try {
      const { app, username, encryptionKey } = req.query;
  
      if (!app || !username || !encryptionKey) {
        res.status(400).json({ error: 'Missing parameters in the request' });
        return;
      }
  
      // Establish the connection
      const dbConnection = await connectToDatabase();
  
      // Retrieve the encrypted password from the database
      const selectQuery = `SELECT password FROM User WHERE app = ? AND username = ?`;
      const selectValues = [app, username];
  
      // Use 'execute' on 'dbConnection' directly for promises
      const [result] = await dbConnection.execute(selectQuery, selectValues);
  
      if (result.length === 0) {
        res.status(404).json({ error: 'Password not found' });
        return;
      }
  
      // Decrypt the password using the provided key
      const encryptedPassword = result[0].password;
      const decipher = crypto.createDecipheriv('aes-128-ecb', Buffer.from(encryptionKey, 'hex'), Buffer.alloc(0));
      let decryptedPassword = decipher.update(encryptedPassword, 'hex', 'utf-8');
      decryptedPassword += decipher.final('utf-8');
  
      res.json({ app, username, password: decryptedPassword });
    } catch (err) {
      console.error('Error retrieving password from database: ', err);
      res.status(500).json({ error: 'Internal Server Error' });
    }
  });
  
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});
