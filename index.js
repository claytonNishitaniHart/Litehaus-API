const express = require('express');
const app = express();
const cors = require('cors');
const argon2 = require('argon2');
const jwt = require('jsonwebtoken');
const cookie_parser = require('cookie-parser');
const { getUsers, postNewUser, findUserByEmail } = require('./db-access-layer');

app.use(cors());
app.use(express.json());
app.use(cookie_parser());

const port = process.env.PORT || 5000;

app.post('/api/refresh_token', async (req, res) => {
  const token = req.cookies.jid;

  if (!token) {
    return res.status(400).json({ error: 'no token' });
  }

  let payload = {};
  try {
    payload = jwt.verify(token, process.env.REFRESH_SECRET);
  } catch (error) {
    return res.status(400).json({ error: error.message });
  }

  const newPayload = {
    sub: payload.sub,
    name: payload.name,
    iss: 'litehaus'
  };

  const newAccessToken = jwt.sign(newPayload, process.env.SECRET, { expiresIn: '15m' });
  res.cookie('jid', jwt.sign(newPayload, process.env.REFRESH_SECRET, { expiresIn: '7d' }), { httpOnly: true });
  return res.status(201).json({ success: true, accessToken: newAccessToken });
});

app.get('/api/users', async (req, res) => {
  try {
    const users = await getUsers();
    return res.status(200).json(users);
  } catch (error) {

  }
});

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
    const REFRESH_SECRET = process.env.REFRESH_SECRET;
    const token = jwt.sign(payload, SECRET, { expiresIn: '15m' });
    res.cookie('jid', jwt.sign(payload, REFRESH_SECRET, { expiresIn: '7d' }), { httpOnly: true });

    return res.status(200).json({ success: 'user authenticated', token: token });
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
      return res.status(400).json({ error: 'user already exists', user: userExists });
    }

    const hashedPassword = await argon2.hash(password);
    const user = await postNewUser(name, email, hashedPassword);
    if (user.error == 500) {
      return res.status(500).json({ error: user.error, message: user.message });
    }
    return res.status(201).json(user);
  } catch (error) {
    return res.status(500).json({ error: 500, message: error.message });
  }
});

app.listen(port, () => {
  console.log(`listening on port ${port}`);
});