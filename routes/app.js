// libs
const {Router} = require('express')
const router = Router()
const md5 = require('js-md5')
// url API
let api = require('../controllers/api-v1.0')
const url = '/api/v1.0'

// Auth
router.route(url+'/signin').post(api.signIn)
router.route(url+'/signup').post(api.signUp)
router.route(url+'/new-password').post(api.newPassword)

// For all users
router.route(url+'/logs').post(api.logs)

// For Admins
router.route(url+'/admin/users').post(api.users)

// Connect to server
router.route(url+'/connect').post(api.connect)

// If page not found
router.route('/*').get(api.notFound).post(api.notFound)

module.exports = router