const {Schema, model} = require('mongoose')

const devicesSchema = new Schema({
    name: String,
    about: String,
    type: String
})

module.exports = model('devices', devicesSchema)