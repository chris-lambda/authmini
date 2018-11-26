const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');

const db = require('./database/dbConfig.js');

const server = express();

server.use(express.json());
server.use(cors());

server.get('/', (req, res) => {
  res.send('Its Alive!');
});

server.post('/api/login', (req, res) => {
  // grab username and password
  const creds = req.body;

  db('users').where({username: creds.username}).first()
  .then(user => {
    if(user && bcrypt.compareSync(creds.password, user.password)) {
      res.status(201).json({message: 'can longin'})
    } else {
      res.status(401).json({message: 'you shall not pass!'})
    }
  })
  .catch(err => console.log(err));
})

server.post('/api/register', (req, res) => {
  // grab username and password
  const creds = req.body;

  // generate the hash from users password
  const hash = bcrypt.hashSync(creds.password, 14) // rounds 2 ^ X

  // override the user.password with hashed password
  creds.password = hash

  // save user to db
  db('users').insert(creds)
  .then(ids => res.status(201).json(ids))
  .catch(err => console.log(err))
})

// protect this route, only authenticated users should see it
server.get('/api/users', (req, res) => {
  db('users')
    .select('id', 'username', 'password') // added password to the select
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
