const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const session = require('express-session');
const KnexSessionStore = require('connect-session-knex')(session);

const db = require('./database/dbConfig.js');

const server = express();

const sessionConfig = {
  // keep secret, name in env variables
  name: 'mankey',
  secret: 'cnj4ni3n3934fnfn0niffjknv',
  cookie : {
    maxAge: 1000 * 60 * 10,
    secure: false, // only set it over https; in production you want this to be true
  },
  httpOnly: true,
  resave: false,
  saveUninitialized: false,
  store: new KnexSessionStore({
    tablename: 'session',
    sidfieldname: 'sid',
    knex: db,
    createTable: true,
    clearInterval: 1000 * 60 * 10
  })
}

const protected = (req, res, next) => {
  req.session && req.session.userId 
    ? next() 
    : res.status(401).json({message: 'you shall not pass!'})
}

server.use(session(sessionConfig))
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
      req.session.userId = user.id;
      res.status(201).json({message: 'can longin'})
    } else {
      res.status(401).json({message: 'you shall not pass!'})
    }
  })
  .catch(err => console.log(err));
})

server.get('/api/logout', (req, res) => {

  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        res.send('you can never leave')
      } else {
        res.send('bye')
      }
    })
  } else {
    res.end();
  }
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
server.get('/api/users', protected, (req, res) => {
  db('users')
    .select('id', 'username', 'password') // added password to the select
    .then(users => {
      res.json(users);
    })
    .catch(err => res.send(err));
});

server.listen(3300, () => console.log('\nrunning on port 3300\n'));
