const {Schema, model} = require('mongoose')

const userSchema = new Schema({
    login: String,
    password:  String,
    salt: String,
    email: String,
    phone: String,
    about: String,
    imgSrc: {
        type: String,
        default: 'https://res.cloudinary.com/adas/image/upload/v1605162780/devices/dqr6pvy9guow0dwg9s8y.jpg'
    },
    new_password: Boolean,
    new_password_hash: String,
    vk_uid: {
        type: String,
        default: ''
    },
    google_uid: {
        type: String,
        default: ''
    },
    ya_uid: {
        type: String,
        default: ''
    },
    type: {
        type: Number,
        default: 0
    },
    code: String,
    created: { 
        type: Date,
        default: Date.now
    }
})

module.exports = model('users', userSchema)