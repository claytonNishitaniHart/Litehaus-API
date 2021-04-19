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

const getSymbolsById = async (id) => {
  try {
    const symbols = await pool.query(
      'SELECT symbols FROM users WHERE id=$1',
      [id]
    );
    return symbols.rows[0].symbols;
  } catch (error) {
    return { error };
  }
};

const postNewSymbol = async (id, symbol) => {
  try {
    const newSymbols = await getSymbolsById(id);
    newSymbols = newSymbols + ',' + symbol;
    const updateSymbols = await pool.query(
      'UPDATE users SET symbols=$2 WHERE id=$1',
      [id, newSymbols]
    );
    return updateSymbols.rows[0];
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
  getSymbolsById,
  postNewSymbol,
  findUserByEmail
};