const {Router, response} = require('express')
const router = Router()
const md5 = require('js-md5')
const axios = require('axios')
const moment = require('moment')
const nodeSid = require('node-sid');
const jwt = require('jsonwebtoken');
const config = require('../config/secret');

moment.locale('ru')

const devicesSchema = require('../models/devices')
const accountingSchema = require('../models/accounting')
const usersSchema = require('../models/users')
const logsSchema = require('../models/logs')

var check = require('../scripts/check')
var hsh = require('../scripts/hash')

exports.signIn = async (req, res) => {
    let response = {}
    if (!req.body.login || !req.body.password) {
        response = {
            errorType: 'login',
            error: 'Необходимо заполнить все поля.'
        }
    } else {
        const user = await usersSchema.findOne({$or: [{login: req.body.login.toLocaleLowerCase()}, {email: req.body.login.toLocaleLowerCase()}]})
        if (!user) {
            response = {
                errorType: 'login',
                error: 'Логин не существует или введён неверно.',
            }
        } else {
            if (hsh.getHash(req.body.password, user.salt) == user.password){    
                if (user.new_password) {   
                    let token = jwt.sign({ _id: user._id }, config.secret, { expiresIn: 86000 });
                    response = {
                        new_password_hash: user.new_password_hash,
                        token: token
                    }
                } 
                let token = jwt.sign({ _id: user._id }, config.secret, { expiresIn: 86000 });
                console.log('Пользователь (_id: '+user._id+') вошёл в систему. token: ' + token) 
                let type = '';
                if (user.type == 1)
                    type = 'Администратор'
                else if (user.type == 0)
                    type = 'Не подтвержден'
                else if (user.type == 2)
                    type = 'Студент'
                response = Object.assign(response, {
                    auth: true,
                    token: token,
                    user: {
                        _id: user._id,
                        login: user.login,
                        isAdmin: user.type == 1,
                        isBlock: user.type == 0,
                        about: user.about,
                        eMail: user.email,
                        phone: user.phone,
                        code: user.code,
                        type: type,
                        imgSrc: user.imgSrc
                    }
                })
            } else {
                response = {
                    errorType: 'password',
                    error: 'Пароль введен неверно.'
                }
            }
        }
    }
    res.send({
        response
    })
}

exports.signUp = async (req, res) => {
    let response = {}
    if (!req.body.about || !req.body.login || !req.body.eMail || !req.body.phone || !req.body.password) {
        response = {
            errorType: 'login',
            error: 'Необходимо заполнить все поля.'
        }
    } else {
        const userL = await usersSchema.findOne({login: req.body.login.toLocaleLowerCase()})
        const userE = await usersSchema.findOne({email: req.body.eMail})
        if (userL) {
            response = {
                errorType: 'login',
                error: 'Логин занят.'
            }
        } else if (userE) {
            response = {
                errorType: 'eMail',
                error: 'Почта уже используется.'
            }
        } else if (req.body.password == '1234567890') {
            response = {
                errorType: 'password',
                error: 'Пароль не должен совпадать со стандартным.'
            }
        } else {
            const salt = hsh.getSalt('', 8);
            const new_user = new usersSchema({
                about: req.body.about,
                login: req.body.login.toLocaleLowerCase(),
                email:  req.body.eMail,
                phone:  req.body.phone,
                password:  hsh.getHash(req.body.password, salt),
                salt: salt,
                vk_uid: '',
                ya_uid: '',
                google_uid: ''
            })
            await new_user.save();
            response = {
                status: 200
            }
        }
    }
    res.send({
        response    
    })
}

exports.connect = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token', connect: true})
    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    connect: true,
                    logout: true
                })
                return
            } else {
                console.log(err.name)             
                res.send({
                    connect: true
                })
            }    
        } else {              
            res.send({
                connect: true
            })
        }

    })
}

exports.logs = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            var logs = await logsSchema.find({}).lean() 
            for (var i = 0; i < logs.length; i++){
                user = await usersSchema.findById(logs[i].user_id).lean();
                logs[i].user = user ? user.about : logs[i].user_id + ' (Пользователь удалён из базы)';
                accounting = await accountingSchema.findById(logs[i].device_id);
                var device = '';
                if (accounting)
                    device = await devicesSchema.findById(accounting.device_id).lean();
                logs[i].device = device ? device.name : logs[i].device_id + ' (Устройство удалено из базы)';
                logs[i].received = moment(logs[i].received).utcOffset('GMT+07:00').format('lll');
                if (logs[i].returned)
                    logs[i].returned = moment(logs[i].returned).utcOffset('GMT+07:00').format('lll');
                else    
                    logs[i].returned = "На руках"
            }
            res.send({
                logs
            })
        }

    })
}

exports.users = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            if (req.body.search)  {
                console.log(1)
                var usersFull = await usersSchema.find({ 
                    $or: [ 
                        { about: { $regex: req.body.search, $options: '-i' } }, 
                        { login: { $regex: req.body.search, $options: '-i'  } },
                        { email: { $regex: req.body.search, $options: '-i'  } },
                        { phone: { $regex: req.body.search, $options: '-i'  } }
                    ] 
                }).lean()  
            } else var usersFull = await usersSchema.find({}).lean()
            let users = []
            var date = new Date()
            var new_code = '7'+(date.getSeconds()+10)+''+date.getTime()
            for (i = 0; usersFull.length > i; i++) {
                users[i] = {
                    _id: usersFull[i]._id,
                    login: usersFull[i].login,
                    about: usersFull[i].about,
                    eMail: usersFull[i].email,
                    phone: usersFull[i].phone,
                    code: usersFull[i].code,
                    new_password: usersFull[i].new_password,
                    imgSrc: usersFull[i].imgSrc,
                    typeNum: usersFull[i].type
                }
                if (usersFull[i].type == 1)
                    users[i].type = 'Администратор'
                else if (usersFull[i].type == 0)
                    users[i].type = 'Не подтвержден'
                else if (usersFull[i].type == 2)
                    users[i].type = 'Студент'
                if (!usersFull[i].code) {
                    users[i].code = new_code
                }
            }
            res.send({
                users
            })
        }

    })
}

exports.onHands = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            let acc = await accountingSchema.find({taken: req.body._id})
            const have = []
            for (let i = 0; i < acc.length; i++) {
                var device = await devicesSchema.findOne({_id: acc[i].device_id}).lean()
                have[i] = Object.assign({name: device.name}, acc[i])
            }
            res.send({
                have
            })
        }

    })
}


exports.userEdit = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {            
            let Luser = await usersSchema.findById(req.body.user._id).lean()
            let new_user = {}
            let date = new Date()
            let new_code = '7'+(date.getSeconds()+10)+''+date.getTime()
            if (Luser) {
                await usersSchema.findByIdAndUpdate(req.body.user._id, {
                    about: req.body.user.about,
                    login: req.body.user.login.toLocaleLowerCase(),
                    email: req.body.user.eMail,
                    phone: req.body.user.phone,
                    type: req.body.user.typeNum,
                    imgSrc: req.body.user.imgSrc
                })
            } else {
                const salt = hsh.getSalt('', 8);
                new_user = new usersSchema({
                    about: req.body.user.about,
                    login: req.body.user.login.toLocaleLowerCase(),
                    email: req.body.user.eMail,
                    phone: req.body.user.phone,
                    imgSrc: req.body.user.imgSrc,
                    password: hsh.getHash('1234567890', salt),
                    code: new_code,
                    salt: salt,
                    vk_uid: '',
                    ya_uid: '',
                    google_uid: ''
                })
                await user.save();
            }
            let user = await usersSchema.findById(req.body.user._id).lean()
            users = {
                _id: user._id,
                login: user.login,
                about: user.about,
                eMail: user.email,
                phone: user.phone,
                code: user.code,
                new_password: user.new_password,
                imgSrc: user.imgSrc,
                typeNum: user.type
            }
            if (user.type == 1)
                users.type = 'Администратор'
            else if (user.type == 0)
                users.type = 'Не подтвержден'
            else if (user.type == 2)
                users.type = 'Студент'
            res.send({
                user: users
            })
        }

    })
}

exports.userDelete = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {  
            await usersSchema.findByIdAndDelete(req.body._id)
            res.send({
                status: 200
            })
        }

    })
}

exports.userResetPassword = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {  
            const salt = hsh.getSalt('', 8);
            let new_user = await usersSchema.findByIdAndUpdate(req.body._id, {
                new_password: true,
                new_password_hash: hsh.getSalt('', 32),
                password:  hsh.getHash('1234567890', salt),
                salt: salt,
            })
            users = {
                _id: req.body._id,
                login: new_user.login,
                about: new_user.about,
                eMail: new_user.email,
                phone: new_user.phone,
                code: new_user.code,
                new_password: true,
                imgSrc: new_user.imgSrc,
                typeNum: new_user.type
            }
            if (new_user.type == 1)
                users.type = 'Администратор'
            else if (new_user.type == 0)
                users.type = 'Не подтвержден'
            else if (new_user.type == 2)
                users.type = 'Студент'
            res.send({
                user: users
            })
        }

    })
}

exports.userNewPassword = async (req, res) => {
    let token = req.body.token;
    let response = {}
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {  
            const user = await usersSchema.findById(req.body._id)       
            if (user.new_password_hash != req.body.hash) { 
                res.send({
                    logout: true
                })
                return
            } else
            if (!req.body.password || !req.body.password2) { 
                response = {
                    errorType: 'password',
                    error: 'Заполните все поля!'
                }            
            } else if (user.password == hsh.getHash(req.body.password, user.salt)) {                 
                response = {
                    errorType: 'password',
                    error: 'Новый пароль не должен совпадать со стандартным.'
                }
            } else if (req.body.password == req.body.password2) {   
                const salt = hsh.getSalt('', 8);
                await usersSchema.findByIdAndUpdate(req.body._id, {'password': hsh.getHash(req.body.password, salt), 'salt': salt, 'new_password': false, 'new_password_hash': ''})
                console.log('Пользователь (_id: '+req.body._id+') удачно сменил пароль.');
                response = {
                    auth: true
                }
            } else {      
                response = {
                    errorType: 'password',
                    error: 'Пароли не совпадают.'
                }
            }
            res.send({
                response
            })
        }

    })
}

exports.devices = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            let devices = await devicesSchema.find({}).lean()
            res.send({
                devices
            })
        }

    })
}

exports.devicesSearch = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {   
            let devices = []
            if (req.body.search)          
                devices = await devicesSchema.find({ 
                    $or: [ 
                        { name: { $regex: req.body.search, $options: '-i'  } },
                        { about: { $regex: req.body.search, $options: '-i'  } },
                        { type: { $regex: req.body.search, $options: '-i'  } }
                    ] 
                }).lean()
            else devices = await devicesSchema.find({}).lean()
            for (let i = 0; i < devices.length; i++) {
                devices[i].accounting404 = await accountingSchema.find({device_id: devices[i]._id, place: '404', taken: 0}).countDocuments()
                devices[i].accounting707 = await accountingSchema.find({device_id: devices[i]._id, place: '707', taken: 0}).countDocuments()
            }
            res.send({
                devices
            })
        }

    })
}

exports.deviceEdit = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {    
            console.log(req.body)         
            let device = await devicesSchema.findById(req.body._id).lean()
            if (device) {
                await devicesSchema.findByIdAndUpdate(req.body._id, {
                    name: req.body.name,
                    about: req.body.about,
                    imgSrc: req.body.imgSrc,
                    type: req.body.type
                })
            } else {
                let new_device = new devicesSchema({
                    name: req.body.name,
                    about: req.body.about,
                    imgSrc: req.body.imgSrc,
                    type: req.body.type
                })
                await new_device.save()
            }
            res.send({
                status: 200
            })
        }

    })
}

exports.deviceDelete = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {  
            await devicesSchema.findByIdAndDelete(req.body._id)
            res.send({
                status: 200
            })
        }

    })
}

exports.accounting = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            if (req.body.search)          
                devices = await devicesSchema.find({ 
                    $or: [ 
                        { name: { $regex: req.body.search, $options: '-i'  } },
                        { about: { $regex: req.body.search, $options: '-i'  } },
                        { type: { $regex: req.body.search, $options: '-i'  } }
                    ] 
                }).lean()
            else devices = await devicesSchema.find({}).lean()
            for (let i = 0; i < devices.length; i++) {
                let acc = await accountingSchema.find({device_id: devices[i]._id})
                devices[i].accounting = acc
            }
            res.send({
                devices
            })
        }

    })
}

exports.accountingAdd = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            let new_accounting = new accountingSchema({
                device_id: req.body.device_id,
                code: req.body.code,
                place: req.body.place,
                note: req.body.note
            })
            await new_accounting.save()
            res.send({
                status: 200
            })
        }

    })
}

exports.accountingEdit = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            await accountingSchema.findByIdAndUpdate(req.body._id, {
                note: req.body.note, 
                place: req.body.place
            })
            res.send({
                status: 200
            })
        }

    })
}

exports.accountingDelete = async (req, res) => {
    let token = req.headers['x-access-token'];
    if (!token) res.send({error: 'No access token'})

    jwt.verify(token, config.secret, async function(err, decoded) {
        if (err) {
            if(err.name == 'TokenExpiredError') {
                console.log('Token Expired Error')
                res.send({
                    logout: true
                })
                return
            } else {
                console.log(err.name)
            }    
        } else {             
            await accountingSchema.findByIdAndDelete(req.body._id)
            res.send({
                status: 200
            })
        }

    })
}

exports.notFound = async (req, res) => {
    res.status(404).send({
        status: 404,
        text: 'Page not found'
    })
}