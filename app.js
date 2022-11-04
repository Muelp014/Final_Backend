var express = require("express");
var cors = require("cors");
var app = express();
var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require('bcrypt');
const saltRounds = 10;
var jwt = require('jsonwebtoken');
const secret = 'Fullstack-Login-2022'


app.use(cors());

const mysql = require("mysql2");

// create the connection to database
const connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  database: "lp",
});

app.post("/register", jsonParser, function (req, res, next) {
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
        connection.execute(
            "INSERT INTO user (email, password, fname, iname) VALUES (?, ?, ?, ?) ",
            [req.body.email, hash, req.body.fname, req.body.iname],
            function (err, results, fields) {
                if (err) {
                    res.json({status: 'error', message: err})
                    return   
                }
                res.json({status: 'ok'})
            }
          );
    });

});

app.post("/login", jsonParser, function (req, res, next){
    connection.execute(
        "SELECT * FROM user WHERE email = ? ",
        [req.body.email],
        function (err, user, fields) {
            if (err) {res.json({status: 'error', message: err}); return }
            if(user.length == 0) {res.json({status: 'error', message: 'no user found'}); return }
            bcrypt.compare(req.body.password, user[0].password, function(err, isLogin) {
                if (isLogin){
                    var token = jwt.sign({ email: user[0].email }, secret, { expiresIn: '1h' });
                    res.json({status: 'ok', message: 'login success', token})
                } else {
                    res.json({status: 'error', message: 'login failed'})
                }
            });
        }
      );
})


app.post("/authen", jsonParser, function (req, res, next){
    try{
    const token = req.headers.authorization.split(' ')[1]
    var decoded = jwt.verify(token, secret);
    res.json({status: 'ok', decoded})
    } catch(err) {
        res.json({status: 'error', message: err.message})
    }
})

app.listen(3033, jsonParser, function () {
  console.log("CORS-enabled web server listening on port 3033");
});
