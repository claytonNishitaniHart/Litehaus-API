const express = require('express');
const app = express();
const cors = require('cors');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const { postNewUser, findUserByEmail } = require('./db-access-layer');

app.use(cors());
app.use(express.json());

const port = process.env.PORT || 5000;

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      res.status(400).json({ error: 'email and password required' });
    }

    const userExists = await findUserByEmail(email);
    if (!userExists) {
      return res.status(404).json({ error: 'user not found' });
    }

    if (!(await argon2.verify(userExists.password, password))) {
      return res.status(401).json({ error: 'Incorrect password' });
    }

    const payload = {
      sub: email,
      name: userExists.name,
      iss: 'litehaus'
    };

    const SECRET = process.env.SECRET;
    const token = jwt.sign(payload, SECRET);

    return res.status(200).json({ success: 'User authenticated', token: token });
  } catch (error) {
    return res.status(500).json({ error: 500, message: error.message });
  }
});

app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ error: 'name, email, and password required' });
    }

    const userExists = await findUserByEmail(email);

    if (userExists) {
      return res.status(400).json({ error: 'user already exists' });
    }

    const hashedPassword = await argon2.hash(password);
    const user = await postNewUser(name, email, hashedPassword);
    if (user.error == 500) {
      return res.status(500).json({ error: user.error, message: user.message });
    }
    console.log(user);
    return res.status(201).json(user);
  } catch (error) {
    return res.status(500).json({ error: 500, message: error.message });
  }
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});