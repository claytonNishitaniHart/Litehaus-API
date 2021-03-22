const { pool } = require('./config');

const getUsers = async () => {
  try {
    const users = await pool.query(
      'SELECT * FROM users'
    );
    return users.rows;
  } catch (error) {

  }
}

const postNewUser = async (name, email, hashedPassword) => {
  try {
    const newUser = await pool.query(
      'INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *',
      [name, email, hashedPassword]
    );
    return newUser.rows[0];
  } catch (error) {
    return { error };
  }
};

const findUserByEmail = async (email) => {
  try {
    const user = await pool.query(
      'SELECT * FROM users WHERE email=$1',
      [email]
    );
    return user.rows[0];
  } catch (error) {
    return { error };
  }
}

module.exports = {
  getUsers,
  postNewUser,
  findUserByEmail
};