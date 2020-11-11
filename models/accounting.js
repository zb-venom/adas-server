const {Schema, model} = require('mongoose')

const accountingSchema = new Schema({
    taken: {
        type: String,
        default: '0'
    },
    device_id:  String,
    code: String,
    place: String,
    note: String
})

module.exports = model('accounting', accountingSchema)