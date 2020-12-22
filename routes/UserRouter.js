const express = require('express')
const router = express.Router()

const Authenticator = require('./Authenticator')
const { register, login, getCurrentUser, getUsers } = require('../controllers/Users/UserController')

router.get('/my-info', Authenticator, getCurrentUser)
router.get('/', getUsers)

// http://localhost:3000/users/register
router.post('/register', register)
router.post('/login', login)

module.exports = router