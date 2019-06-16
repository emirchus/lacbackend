const express = require('express');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcrypt-nodejs');
var request = require('request').defaults({
    encoding: null
});

var accountsTokens = [];

//MongoDB
const MongoClient = require('mongodb').MongoClient;
const mongodb_uri = "mongodb+srv://owner:EBHdwNn2sn8uiJRv@liteandb-kxcmm.mongodb.net/test?retryWrites=true";
const mongodb = new MongoClient(mongodb_uri, { useNewUrlParser: true })
var lacdb;
var postdb;
//App
var app = express();
var server = require('http').createServer(app);
var io = require('socket.io')(server);

app.set('port', 3001);
app.use(cors({
    allowedHeaders: 'Content-Type, Cache-Control, application/json'
}));
app.options('*', cors());
app.use(morgan('dev'));
app.use(bodyParser.json({ limit: '50mb' }));
app.use(bodyParser.urlencoded({ limit: '50mb', extended: true }));

const mailjet = require('node-mailjet')
    .connect('d88e3842becfb3a92362a6a66bc45f64', '03c642f460b7531a450efb88430555ed')
//Middlewares

var count = 0;


io.on('connection', function (socket) {
    count++
    io.sockets.emit('broadcast', count + "-conection")
    console.log(count + " people online")
    socket.on('disconnect', function (e) {
        count--;
        io.sockets.emit('broadcast', count + "-disconected")
        console.log(count + " people online")
    });
    socket.on('friendinfo', (data) => {
        console.log(data);
        var status = data.split('-')[0];
        var friendname = data.split('-')[1];
        var serverlog = data.split('-')[1];
        const usersCollections = lacdb.collection('clients');
        if (status === "online") {
            usersCollections.updateOne({ "usernamelower": friendname }, { $set: { "status": true } })
            io.sockets.emit('lfriend', friendname)
        } else {
            usersCollections.updateOne({ "usernamelower": friendname }, { $set: { "status": false } })
            io.sockets.emit('ofriend', friendname)
            if (serverlog) {
                const usr = accountsTokens.find(a => a.username.toLowerCase() === friendname);
                accountsTokens.splice(accountsTokens.indexOf(usr), 1);
            }
        }

    })

    socket.on('oauth', (data) => {
        const obj = JSON.parse(data);
        console.log(data)
        console.log(obj)
        oauth(obj.id, obj.password).then((token) => {
            if (token) {
                let ss = {
                    userid: obj.accessToken,
                    success: token
                }
                io.sockets.emit('oauthsuccess', ss)
            } else {
                let err = {
                    userid: obj.accessToken,
                    error: "wrong error"
                }
                io.sockets.emit('oautherror', err)
            }
        }, (error) => {
            if (error == 1) {
                let err = {
                    userid: obj.accessToken,
                    error: "wrong Password"
                }
                io.sockets.emit('oautherror', err)
            }
            else if (error == 2) {
                let err = {
                    userid: obj.accessToken,
                    error: "user does exists"
                }
                io.sockets.emit('oautherror', err)
            }
            else if (error == 3) {
                let err = {
                    userid: obj.accessToken,
                    error: "invalid arguments"
                }
                io.sockets.emit('oautherror', err)
            }
        })

    })

    socket.on('request', (data) => {

    })

    socket.on('message', (data) => {
        io.sockets.emit('message', data)
    })

    socket.on('request', (data) => {
        data = JSON.parse(data)
        getUser(data.username).then((user) => {
            io.sockets.emit('capereq', JSON.stringify({ capes: user.capes }));
        }, () => {
            console.log("error")
        }).catch(() => {
            console.log("error")
        })
    })

    socket.on('friendaction', data => {
        var action = data.split("-")[0];
        var friendname = data.split("-")[1]
        var from = data.split("-")[2]
        const usersCollections = lacdb.collection('clients');
        console.log(data);
        if (friendname !== from) {
            getUser(from).then((user) => {
                if (action === "remove") {
                    if (user.friends.find(x => x === friendname)) {
                        usersCollections.findOne({ 'usernamelower': friendname }, (err, euser) => {
                            if (euser) {
                                usersCollections.updateOne({ 'usernamelower': friendname }, { $pull: { 'friends': from } }, (err) => {
                                    usersCollections.updateOne({ 'usernamelower': from }, { $pull: { 'friends': friendname } }, (err, r) => {
                                        io.sockets.emit('friendrequest', "removed-" + from + "-" + friendname);
                                    })
                                })
                            } else {
                                io.sockets.emit('error', "Not found the user-" + friendname + "-" + from);
                            }
                        });
                    } else {
                        io.sockets.emit('error', "You are not the friend of-" + friendname + "-" + from)
                    }
                }
                if (action === "add") {
                    if (!user.friends.find(x => x === friendname)) {
                        if (!user.friendsends.find(x => x === friendname)) {
                            if (!user.friendrequest.find(x => x === friendname)) {
                                usersCollections.findOne({ 'usernamelower': friendname }, (err, euser) => {
                                    if (euser) {
                                        usersCollections.updateOne({ 'usernamelower': friendname }, { $push: { 'friendres': from } }, (err) => {
                                            usersCollections.updateOne({ 'usernamelower': from }, { $push: { 'friendsend': friendname } }, (err, r) => {
                                                io.sockets.emit('friendrequest', "request-" + from + "-" + friendname);
                                                io.sockets.emit('friendrequest', "send-" + friendname + "-" + from);
                                            })
                                        })
                                    } else {
                                        io.sockets.emit('error', "Not found your-friend" + "-" + from)
                                    }
                                });
                            } else {
                                addFriend(from, friendname).then(() => {
                                    io.sockets.emit('friendrequest', "accepted-" + from + "-" + friendname);
                                }, (er) => {
                                    if (er === 1) {
                                        io.sockets.emit('error', "You are already are friend of-" + friendname + "-" + from)
                                    }
                                    else if (er === 2) {
                                        io.sockets.emit('error', "Not found the user-" + friendname + "-" + from);
                                    }
                                    else {
                                        io.sockets.emit('error', " -" + er + "-" + from);
                                    }
                                })
                            }
                        } else {
                            io.sockets.emit('error', "You already send request to-" + friendname + "-" + from)
                        }
                    } else {
                        io.sockets.emit('error', "You are already are friend of-" + friendname + "-" + from)
                    }

                }
                else if (action === "accept") {
                    if (!user.friends.find(x => x === friendname)) {
                        if (!user.friendsends.find(x => x === friendname)) {
                            if (user.friendrequest.find(x => x === friendname)) {
                                addFriend(from, friendname).then((sf, err) => {
                                    if (err) {
                                        io.sockets.emit('error', "Not found your-friend" + "-" + from)
                                    } else {
                                        io.sockets.emit('friendrequest', "accepted-" + from + "-" + friendname);
                                    }
                                })
                            } else {
                                io.sockets.emit('error', " You do not have an " + friendname + "-request-" + from)
                            }
                        } else {
                            usersCollections.updateOne({ 'usernamelower': friendname }, { $push: { 'friendres': from } }, (err) => {
                                usersCollections.updateOne({ 'usernamelower': from }, { $push: { 'friendsend': friendname } }, (err, r) => {
                                    io.sockets.emit('friendrequest', "request-" + from + "-" + friendname);
                                    io.sockets.emit('friendrequest', "send-" + friendname + "-" + from);
                                })
                            })
                        }
                    } else {
                        io.sockets.emit('error', "You are already are friend of-" + friendname + "-" + from)
                    }
                } else if (action === "denied") {
                    if (!user.friends.find(x => x === friendname)) {
                        if (user.friendrequest.find(x => x === friendname)) {
                            usersCollections.findOne({ 'usernamelower': friendname }, (err, euser) => {
                                if (euser) {
                                    usersCollections.updateOne({ 'usernamelower': friendname }, { $pull: { 'friendres': from } }, (err) => {
                                        usersCollections.updateOne({ 'usernamelower': from }, { $pull: { 'friendsend': friendname } }, (err, r) => {
                                            io.sockets.emit('friendrequest', "denied-" + from + "-" + friendname);
                                        })
                                    })
                                } else {
                                    io.sockets.emit('error', "Not found the user-" + friendname + "-" + from);
                                }
                            });
                        }
                        else if (user.friendsends.find(x => x === friendname)) {
                            usersCollections.findOne({ 'usernamelower': friendname }, (err, euser) => {
                                if (euser) {
                                    usersCollections.updateOne({ 'usernamelower': friendname }, { $pull: { 'friendres': from } }, (err) => {
                                        usersCollections.updateOne({ 'usernamelower': from }, { $pull: { 'friendsend': friendname } }, (err, r) => {
                                            io.sockets.emit('friendrequest', "denied-" + friendname + "-" + from);
                                        })
                                    })
                                } else {
                                    io.sockets.emit('error', "Not found the user-" + friendname + "-" + from);
                                }
                            });
                        }
                    } else {
                        io.sockets.emit('error', "You are already are friend of-" + friendname + "-" + from)
                    }
                }


            })
        }

    })
});

app.get('/', (req, res) => {
    res.set('Content-Type', 'text/html');
    if (lacdb) {
        res.send(`Server: \n Online \n Server on: ${app.get('port')}`);
    } else {
        res.send(`Server: \n Disable \n Server on: ${app.get('port')}`);
    }
})

app.get('/post', (req, res) => {
    res.set('Content-Type', 'text/html');
    if (lacdb) {
        res.sendFile(path.join(__dirname + "/index.html"));
    }
})

app.post('/signup', (req, res) => {
    let email = req.body.email;
    var password = req.body.password;
    var username = req.body.username;
    var photuri = req.body.photopic;
    var usernamelower = username.toLowerCase();
    const usersCollections = lacdb.collection('clients');
    var ip = getClientIP(req, res).IP;
    var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
    if (email && password && username) {
        usersCollections.findOne({ 'usernamelower': usernamelower }, (err, user) => {
            if (!user) {
                usersCollections.findOne({ 'email': email }, (errt, result) => {
                    if (errt) {
                        res.send({ "error": errt })
                    }
                    if (!result) {
                        usersCollections.insertOne({
                            username: username,
                            usernamelower: usernamelower,
                            email: req.body.email,
                            password: bcrypt.hashSync(req.body.password, bcrypt.genSaltSync(8)),
                            registrationIP: ip,
                            verified: false,
                            verifiedToken: token,
                            friendsend: [],
                            friendres: [],
                            friends: [],
                            skin: "",
                            punishments: [],
                            last_login: "",
                            last_address: ip,
                            capes: [],
                            customcape: "",
                            status: false,
                            signupdate: Date.now(),
                            photourl: photuri

                        }, (err, result) => {
                            var sendEmail = mailjet.post("send", { 'version': 'v3.1' })

                            var Emails = {
                                "Messages": [
                                    {
                                        "From": {
                                            "Email": "support@liteanticheat.com",
                                            "Name": "LiteAntiCheat"
                                        },
                                        "To": [
                                            {
                                                "Email": email,
                                                "Name": username
                                            }
                                        ],
                                        "TemplateID": 875856,
                                        "TemplateLanguage": true,
                                        "Subject": "Verify account",
                                        "Variables": {
                                            "username": username,
                                            "accesstoken": token
                                        }
                                    }
                                ]
                            }

                            sendEmail.request(Emails).then((handlePostResponse) => {
                                console.log("Mail sent to " + email);
                                console.log(handlePostResponse.body);

                            }).catch((handleError) => {
                                console.log(handleError)
                            });

                            res.send(result);
                        })
                    } else {
                        res.send({ "error": "account already exists" })
                    }

                })
            } else {
                res.send({ "error": "username already exists" })
            }
        })
    } else {
        res.send({ "error": "username already exists" })
    }
})

function validateEmail(email) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

app.post('/signin', (req, res) => {
    let email = req.body.email;
    var password = req.body.password;
    const usersCollections = lacdb.collection('clients');
    if (email && password) {
        if (validateEmail(email)) {
            usersCollections.findOne({ 'email': email }, (err, result) => {
                if (result) {
                    var ress = bcrypt.compareSync(password, result.password);
                    if (ress === true) {
                        var ip = getClientIP(req, res).IP;
                        const exists = accountsTokens.find(a => a.email === result.email);
                        if (exists) {
                            if (result.verified) {
                                res.send({
                                    sessionid: exists.sessionid,
                                });
                            } else {
                                res.send({
                                    sessionid: exists.sessionid,
                                    data: "need verifier"
                                });
                            }
                            usersCollections.updateOne({ "email": email }, { $set: { "last_login": Date.now(), "last_address": ip, "status": true } })
                        } else {
                            var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
                            accountsTokens.push({
                                email: result.email,
                                id: result._id,
                                uuid: result.verifiedToken,
                                username: result.username,
                                capes: result.capes,
                                photo: result.photourl,
                                sessionid: token,
                                timestamp: Date.now(),
                                signupdate: result.signupdate,
                                verified: result.verified
                            })
                            if (result.verified) {
                                res.send({
                                    sessionid: token,
                                });
                            } else {
                                res.send({
                                    sessionid: token,
                                    data: 'need verifier ' + result.verifiedToken
                                });
                            }
                            usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "last_address": ip, "status": true } })
                        }
                    } else {
                        var dd = new Error('Wrong password.')
                        dd.status = 402;
                        res.send(dd);
                    }
                } else {
                    if (err) {
                        var dd = new Error('User does exists.')
                        dd.status = 405;
                        res.send(dd);
                    }
                    var dd = new Error('User does exists.')
                    dd.status = 405;
                    dd.message = "User does exists";
                    res.send(dd);
                }
            })
        } else {
            usersCollections.findOne({ 'usernamelower': email.toLowerCase() }, (err, result) => {
                if (result) {
                    var ress = bcrypt.compareSync(password, result.password);
                    if (ress === true) {
                        var ip = getClientIP(req, res).IP;
                        const exists = accountsTokens.find(a => a.email === result.email);
                        if (exists) {
                            if (result.verified) {
                                res.send({
                                    sessionid: exists.sessionid,
                                });
                            } else {
                                res.send({
                                    sessionid: exists.sessionid,
                                    data: "need verifier"
                                });
                            }
                            usersCollections.updateOne({ "email": email }, { $set: { "last_login": Date.now(), "last_address": ip, "status": true } })
                        } else {
                            var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
                            accountsTokens.push({
                                email: result.email,
                                id: result._id,
                                uuid: result.verifiedToken,
                                username: result.username,
                                capes: result.capes,
                                photo: result.photourl,
                                sessionid: token,
                                timestamp: Date.now(),
                                signupdate: result.signupdate,
                                verified: result.verified
                            })
                            if (result.verified) {
                                res.send({
                                    sessionid: token,
                                });
                            } else {
                                res.send({
                                    sessionid: token,
                                    data: 'need verifier ' + result.verifiedToken
                                });
                            }
                            usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "last_address": ip, "status": true } })
                        }
                    } else {
                        var dd = new Error('Wrong password.')
                        dd.status = 402;
                        res.send(dd);
                    }
                } else {
                    if (err) {
                        var dd = new Error('User does exists.')
                        dd.status = 405;
                        res.send(dd);
                    }
                    var dd = new Error('User does exists.')
                    dd.status = 405;
                    dd.message = "User does exists";
                    res.send(dd);
                }
            })
        }
    }

})


app.post('/verifiedaccount', (req, res) => {
    var token = req.body.token;
    const db = lacdb.collection('clients');
    if (token) {
        db.findOne({ 'verifiedToken': token }, (err, result) => {
            if (result) {
                if (result.verified) {
                    res.send({ "result": 'is already verified' })
                } else {
                    db.updateOne({ 'verifiedToken': token }, { $set: { 'verified': true } }, (err, ress) => {
                        res.send({ "result": "verified" })
                    })
                }
            } else {
                res.send({ "error": "accounts does exists" })
            }
        })
    }
})

app.post('/authenticate', (req, res) => {
    var sessionid = req.body.sessionid;
    const exists = accountsTokens.find(a => a.sessionid === sessionid);
    if (exists) {
        return res.send(exists)
    } else {
        var err = new Error('Session id not found.');
        err.status = 403;
        return res.send(err);
    }
})

app.post('/updates/get', (req, res) => {
    const db = lacdb.collection('posts');
    db.find({}).toArray((err, docs) => {
        if (err) {
            res.send("error on find posts")
        }
        res.send(docs)
    })

})

app.post('/updates/post', (req, res) => {
    var author = req.body.author;
    var title = req.body.title;
    var date = req.body.date;
    var description = req.body.description;
    var image = req.body.image;
    var pass = req.body.password

    const db = lacdb.collection('posts');
    if (author && title && date && description && image && pass && pass === "letpost666") {
        request.get('https://minotar.net/avatar/' + author, function (error, response, body) {
            if (!error && response.statusCode == 200) {
                var data = "data:" + response.headers["content-type"] + ";base64," + new Buffer(body).toString('base64');

                var post = {
                    title: title,
                    DateTime: date,
                    Author: author,
                    Description: description,
                    AuthorImage: data,
                    Images: image,
                    ip: getClientIP(req, res).IP
                }

                db.insertOne(post, (err, result) => {
                    if (err) {
                        res.send("Error en posteo")
                    } else {
                        io.sockets.emit('updateblog', JSON.stringify(post))
                        console.log(getClientIP(req, res).IP);

                        res.send(result)
                    }
                })


            } else {
                console.log(error)
                res.send(error);
            }
        });

    } else {
        var errorer = new Error("Pass is required");
        if (!author) {
            errorer.name = "author is required";
            errorer.status = 404;
            res.send(errorer);
        }
        if (!description) {
            errorer.name = "description is required";
            errorer.status = 404;
            res.send(errorer);
        }
        if (!title) {
            errorer.name = "title is required";
            errorer.status = 404;
            res.send(errorer);
        }
        if (!image) {
            errorer.name = "image is required";
            errorer.status = 404;
            res.send(errorer);
        }
        if (!date) {
            errorer.name = "date is required";
            errorer.status = 404;
            res.send(errorer);
        }
        if (!pass) {
            errorer.name = "pass is required";
            errorer.status = 404;
            res.send(errorer);
        }
    }

})

app.post('/addaccount', (req, res) => {
    var token = req.body.token;
    let email = req.body.email;
    var uuid = req.body.uuid;
    var accessToken = req.body.accessToken;
    var username = req.body.username;
    var premium = req.body.premium;

    const usersCollections = lacdb.collection('clients');
    if (token) {
        usersCollections.findOne({ 'verifiedToken': token }, (err, user) => {
            if (user) {
                if (err) {
                    console.log(err);
                    res.send(err)
                }
                if (Object.entries(user.mcaccounts).length == 0) {
                    usersCollections.updateOne({ 'verifiedToken': token }, {
                        $set: {
                            'mcaccounts': {
                                "uuid": uuid,
                                "accessToken": accessToken,
                                "email": email,
                                "username": username,
                                "premium": premium,
                                "main": true
                            }
                        }
                    }, (err, ress) => {
                        res.send(err ? err : 'Added corrected')
                    })
                } else {
                    usersCollections.updateOne({ 'verifiedToken': token }, {
                        $push: {
                            'mcaccounts': {
                                "uuid": uuid,
                                "accessToken": accessToken,
                                "email": email,
                                "username": username,
                                "premium": premium,
                                "main": true
                            }
                        }
                    }, (err, ress) => {
                        res.send(err ? err : 'Added corrected')
                    })
                }
            } else {
                res.send('No yser')
            }
        })
    } else {
        res.send('need arguments')
    }

})

app.post('/addfriend', (req, res) => {
    var id = req.body.session;
    var friendname = req.body.friendname;
    const exists = accountsTokens.find(a => a.sessionid === id);
    const usersCollections = lacdb.collection('clients');
    if (id && friendname && exists) {
        usersCollections.findOne({ '_id': exists.id }, (err, cuser) => {
            if (!cuser.friends.find(a => a.friendname === friendname)) {
                usersCollections.findOne({ 'username': friendname }, (err, f) => {
                    if (err)
                        res.send({ 'error': err })
                    if (f) {
                        usersCollections.updateOne({ '_id': exists.id }, { $push: { 'friends': [friendname] } }, (err, r) => {
                            if (err)
                                res.send({ 'error': err })
                            if (r) {
                                res.send({ "success": 'friend added' })
                            } else {
                                res.send({ 'error': 'id does exists' })
                            }

                        })
                    } else {
                        res.send({ 'error': 'friend does exists' })
                    }
                })
            } else {
                res.send('ya lo tiene')
            }

        })
    } else {
        res.send({ "error": "arguments", id, friendname, exists })
    }
})

app.post('/getfriends', (req, res) => {
    var id = req.body.session;
    const exists = accountsTokens.find(a => a.sessionid === id);
    const usersCollections = lacdb.collection('clients');
    if (exists) {
        usersCollections.findOne({ "_id": exists.id }, (err, user) => {
            if (err) {
                res.send(err)
            }
            if (user) {
                res.send(JSON.stringify(user.friends))
            }
        })
    } else {
        res.send({ "error": "session does exists" })
    }
})


app.post('/getfriendsrequest', (req, res) => {
    var id = req.body.session;
    const exists = accountsTokens.find(a => a.sessionid === id);
    const usersCollections = lacdb.collection('clients');
    if (exists) {
        usersCollections.findOne({ "_id": exists.id }, (err, user) => {
            if (err) {
                res.send(err)
            }
            if (user) {
                var total = {
                    "request": [],
                    "send": []
                }
                Array.from(user.friendres).forEach(e => {
                    total.request.push(e)
                })
                Array.from(user.friendsend).forEach(e => {
                    total.send.push(e)
                })
                res.send(JSON.stringify(total));
            }
        })
    } else {
        res.send({ "error": "session does exists" })
    }
})

app.post('/getuser', (req, res) => {
    var user = req.body.user;
    const usersCollections = lacdb.collection('clients');
    if (user) {
        usersCollections.findOne({ 'usernamelower': user }, (err, result) => {
            if (err)
                res.send(err)
            var get = {
                username: result.username,
                email: result.email,
                status: result.status,
                lastlogin: result.last_login,
                verified: result.verified,
                friendrequest: result.friendres,
                friendsends: result.friendsend,
                skin: result.skin,
                capes: result.capes,
                id: result._id,
                signupdate: result.signupdate,
                photourl: result.photourl
            }
            res.send(get);
        })
    }
})

function getUser(name) {
    const usersCollections = lacdb.collection('clients');
    return new Promise((resolve, reject) => {
        if (name) {
            usersCollections.findOne({ 'usernamelower': name }, (err, result) => {
                if (err) {
                    reject(err)
                }
                if (result) {
                    var user = {
                        username: result.username,
                        usernamelower: result.usernamelower,
                        email: result.email,
                        status: result.status,
                        lastlogin: result.last_login,
                        verified: result.verified,
                        friends: result.friends,
                        friendrequest: result.friendres,
                        friendsends: result.friendsend,
                        skin: result.skin,
                        capes: result.capes,
                        id: result._id,
                        signupdate: result.signupdate
                    }
                    resolve(user);
                } else {
                    reject();
                }
            })
        } else {
            reject();
        }
    })
}

function oauth(email, password) {
    const usersCollections = lacdb.collection('clients');
    return new Promise((resolve, reject) => {
        if (email && password) {
            if (validateEmail(email)) {
                usersCollections.findOne({ 'email': email }, (err, result) => {
                    if (result) {
                        var ress = bcrypt.compareSync(password, result.password);
                        if (ress === true) {
                            const exists = accountsTokens.find(a => a.email === result.email);
                            if (exists) {
                                usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "status": true } })
                                resolve(exists.sessionid)
                            } else {
                                var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
                                accountsTokens.push({
                                    email: result.email,
                                    id: result._id,
                                    uuid: result.verifiedToken,
                                    username: result.username,
                                    capes: result.capes,
                                    photo: result.photourl,
                                    sessionid: token,
                                    timestamp: Date.now(),
                                    signupdate: result.signupdate,
                                    verified: result.verified
                                })
                                if (result.verified) {
                                    usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "status": true } })
                                    resolve(token)
                                }
                            }
                        } else {
                            reject(1)
                        }
                    } else {
                        reject(2)
                    }
                })
            } else {
                usersCollections.findOne({ 'usernamelower': email.toLowerCase() }, (err, result) => {
                    if (result) {
                        var ress = bcrypt.compareSync(password, result.password);
                        if (ress === true) {
                            const exists = accountsTokens.find(a => a.email === result.email);
                            if (exists) {
                                usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "status": true } })
                                resolve(exists.sessionid)
                            } else {
                                var token = (Math.random().toString(36).substr(2)) + (Math.random().toString(36).substr(2));
                                accountsTokens.push({
                                    email: result.email,
                                    id: result._id,
                                    uuid: result.verifiedToken,
                                    username: result.username,
                                    capes: result.capes,
                                    photo: result.photourl,
                                    sessionid: token,
                                    timestamp: Date.now(),
                                    signupdate: result.signupdate,
                                    verified: result.verified
                                })
                                usersCollections.updateOne({ "email": result.email }, { $set: { "last_login": Date.now(), "status": true } })
                                resolve(token)
                            }
                        } else {
                            reject(1)
                        }
                    } else {
                        reject(2)
                    }
                })
            }
        } else {
            reject(3)
        }
    })

}

function addFriend(user, friend) {
    const usersCollections = lacdb.collection('clients');
    return new Promise((resolve, reject) => {
        usersCollections.findOne({ 'usernamelower': user }, (err, cuser) => {
            if (!cuser.friends.find(a => a === friend)) {
                usersCollections.findOne({ 'usernamelower': friend }, (err, f) => {
                    if (err)
                        reject(err)
                    if (f) {
                        usersCollections.updateOne({ 'usernamelower': user }, { $push: { 'friends': friend } }, () => {
                            usersCollections.updateOne({ 'usernamelower': friend }, { $push: { 'friends': user } }, () => {
                                usersCollections.updateOne({ 'usernamelower': user }, { $pull: { 'friendsend': friend } }, () => {
                                    usersCollections.updateOne({ 'usernamelower': friend }, { $pull: { 'friendres': user } }, () => {
                                        usersCollections.updateOne({ 'usernamelower': user }, { $pull: { 'friendres': friend } }, () => {
                                            usersCollections.updateOne({ 'usernamelower': friend }, { $pull: { 'friendsend': user } }, () => {
                                                resolve();
                                            })
                                        })
                                    })
                                })
                            })
                        })
                    } else {
                        reject("2")
                    }
                })
            } else {
                reject("1")
            }
        })
    });
}

server.listen(app.get('port'), () => {
    mongodb.connect((err, client) => {
        if (err) {
            console.log(err);
        }
        lacdb = client.db('liteanticheat')
        console.log(`Server on port ${app.get('port')}`);
    })
})


function getClientIP(req, res) {
    try {
        var IPs = req.headers['x-forwarded-for'] ||
            req.connection.remoteAddress ||
            req.socket.remoteAddress ||
            req.connection.socket.remoteAddress;

        if (IPs.indexOf(":") !== -1) {
            IPs = IPs.split(":")[IPs.split(":").length - 1]
        }

        return ({
            IP: IPs.split(",")[0]
        })
    } catch (err) {
        return ({
            message: 'got error'
        });
    }
}
