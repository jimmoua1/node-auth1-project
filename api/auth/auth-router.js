// Require `checkUsernameFree`, `checkUsernameExists` and `checkPasswordLength`
// middleware functions from `auth-middleware.js`. You will need them here!
const router = require('express').Router()
const bcrypt = require('bcryptjs')
const User = require('../users/users-model')

/**
  1 [POST] /api/auth/register { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "user_id": 2,
    "username": "sue"
  }

  response on username taken:
  status 422
  {
    "message": "Username taken"
  }

  response on password three chars or less:
  status 422
  {
    "message": "Password must be longer than 3 chars"
  }
 */
  router.post('/register', (req, res) => {
    const {username, password} = req.body
    const hashed = bcrypt.hashSync(password, 10) 
    User.add({username, password: hashed, role:1}) 
        .then(user => {
            res.status(200).json(user)
        })
        .catch(err => {
            res.status(500).json(err.message)
        })
})


/**
  2 [POST] /api/auth/login { "username": "sue", "password": "1234" }

  response:
  status 200
  {
    "message": "Welcome sue!"
  }

  response on invalid credentials:
  status 401
  {
    "message": "Invalid credentials"
  }
 */
  router.post('/login', async (req, res) => {
    const {username, password} = req.body;

    try {{
        const loggedInUser = await User.findBy({ username }).first()
        if ( loggedInUser && bcrypt.compareSync(password, loggedInUser.password)) {
            req.session.user = loggedInUser
            res.json('access granted')
        } else {
            res.status(401).json('invalid credentials')
        }
    }} catch (err) {
        res.status(500).json(err.message)
    }
})


/**
  3 [GET] /api/auth/logout

  response for logged-in users:
  status 200
  {
    "message": "logged out"
  }

  response for not-logged-in users:
  status 200
  {
    "message": "no session"
  }
 */
  router.get('/logout', (req, res) => {
    if(req.session && req.session.user) {
        req.session.destroy(err => {
            if (err) {
                res.json('You are my slave now')
            } else {
                res.json('see ya')
            }
        })
    } else {
        res.end()
    }
})
 
// Don't forget to add the router to the `exports` object so it can be required in other modules
module.exports = router