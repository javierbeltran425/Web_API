const express = require('express')
const router = express.Router()

const Authenticator = require('./Authenticator')
const { register, login, getCurrentUser, getUsers, updateUser, requestPassword } = require('../controllers/Users/UserController')

router.get('/my-info', Authenticator, getCurrentUser)
router.get('/', getUsers)

router.post('/request-recover', requestPassword)
router.post('/register', register)
router.post('/login', login)

router.put('/update', Authenticator, updateUser)

module.exports = router