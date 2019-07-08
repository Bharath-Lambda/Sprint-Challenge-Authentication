const axios = require('axios');
const knex = require('knex');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const { authenticate } = require('../auth/authenticate');
const dbConfig = require('../knexfile');
const db = knex(dbConfig);
const jwtSecret = process.env.JWT_SECRET;

module.exports = server => {
  server.post('/api/register', register);
  server.post('/api/login', login);
  server.get('/api/jokes', authenticate, getJokes);
};

function generateToken(user) {
  const payload = {
    username: user.username
  };
  const options = {
    expiresIn: '1h'
  };
  return jwt.sign(payload, jwtSecret, options)
}

function register(req, res) {
  const newUser = req.body

  if (newUser.name && newUser.password) {
    newUser.password = bcrypt.hashSync(newUser.password, 14);

    db('users')
      .insert(newUser)
      .then(ids => {
        res.status(201).json(ids);
      })
      .catch(err => res.json(err));
  }
}

function login(req, res) {
  const creds = req.body;

  db('users')
    .where({ username: creds.username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(creds.password, user.password)) {
        req.session.user = user;
        const token = generateToken(user)
        res.status(200).json({ message: 'Logged in', token});
      } else {
        res.status(401).json({ message: 'You shall not pass!'});
      }
    })
    .catch(err => res.json(err));
}

function getJokes(req, res) {
  const requestOptions = {
    headers: { accept: 'application/json' },
  };

  axios
    .get('https://icanhazdadjoke.com/search', requestOptions)
    .then(response => {
      res.status(200).json(response.data.results);
    })
    .catch(err => {
      res.status(500).json({ message: 'Error Fetching Jokes', error: err });
    });
}
