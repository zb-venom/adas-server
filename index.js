const express = require('express')
const mongoose = require('mongoose')
const colors = require('colors');
const bodyParser = require('body-parser')
const morgan = require('morgan')
const cors = require('cors')

const appRoutes = require('./routes/app')
const config = require('./config/default')

const PORT = process.env.PORT || 3000

const app = express()

app.use(express.static(__dirname + '/public'));

app.use(morgan('combined'))
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json())
app.use(cors())
app.use(appRoutes)

const db = 'mongodb+srv://'+config.login+':'+config.password+'@'+config.cluster+'/adas';

async function start() {
    try {
        await mongoose.connect(
            db,
            {
                useNewUrlParser: true,
                useUnifiedTopology: true,
                useFindAndModify: false
            }
        )
        app.listen(PORT, () => {
            console.log(`\nServer started on port ${ PORT }`.green)
        })
    } catch (e) {
        console.log(e)
    }
}

start()