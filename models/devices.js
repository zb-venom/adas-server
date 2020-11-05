const {Schema, model} = require('mongoose')

const devicesSchema = new Schema({
    name: String,
    about: String,
    imgSrc: String,
    type: String
})

module.exports = model('devices', devicesSchema)