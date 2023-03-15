//jshint esversion:6
require('dotenv').config();//for level 2
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
//const encrypt = require("mongoose-encryption");//for level 1,2
//const md5 = require("md5");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

//Place session code here
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));
//Initialize
app.use(passport.initialize());
app.use(passport.session());
//Set up passport-local-mongoose in mongoose



//Connect to DB
mongoose.connect("mongodb://0.0.0.0:27017/userDB");


//Schema
const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//Level 5 ---
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

//Level 1&2(env) security ----------------
// var secret = "ThisIsOurLittleSecret.";
//userSchema.plugin(encrypt, {secret: process.env.SECRET, encryptedFields: ["password"]});

//Level 3 (Hash Fns)
// md5("123") always gives the same encoded value

//Level 4
// Salting & Hashing
//Several rounds of salting


//Level 5
//Cookies & Sessions

//Level 6
//3rd party OAuth - Open Authorisation(token based authorization)



//Model
const User = new mongoose.model("User", userSchema);

//Level 5--- use the plm thing
passport.use(User.createStrategy());
//The 2 lines below this comment are only for local usage & comes from passport-local-mongoose library so we swap it with level 6 google thing so that it works everywhere
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username, name: user.name });
    });
  });
  
  passport.deserializeUser(function(id, cb) {
    // process.nextTick(function() {
    //   return cb(null, user);
    // });
    User.findById(id)
  .then((user) => {
    return cb(null, user);
  })
  .catch((err) => {
    return cb(err, null);
  });
  });
//Follow the order of the code very specifically(Level 6)
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });

  }
));

app.get("/", function(req,res){
    res.render("home");
});
//Level 6
app.get("/auth/google", 
    passport.authenticate("google", {scope: ["profile"]})
);
//Level 6
app.get("/auth/google/secrets", 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect home.
    res.redirect("/secrets");
  });

app.get("/login", function(req,res){
    res.render("login");
});

app.get("/register", function(req,res){
    res.render("register");
});


app.get("/secrets", function(req,res){
    User.find({secret: {$ne:null}}).then((found_users) => {
        res.render("secrets", { usersWithSecrets: found_users});
    }).catch((err) => {
        console.log(err);
    });
});

app.get("/submit", function(req,res){
    if(req.isAuthenticated()){
        res.render("submit");
    }
    else{
        res.redirect("/login");
    };
});

app.get("/logout", function(req,res){
    req.logout(function(err) {
        if (err) { return next(err); }
        res.redirect('/');
      });
});

app.post("/submit", function(req,res){
    const submittedSecret = req.body.secret;
    //console.log(req.user._id);

    User.findById(req.user._id).then((found_user) => {
        found_user.secret = submittedSecret;
        found_user.save().then(() => {
            res.redirect("/secrets");
        }).catch((err) => {
            console.log(err);
        });
    }).catch((err) => {
        console.log(err);
    });
});

app.post("/register", function(req,res){

    // bcrypt.hash(req.body.password,saltRounds, function(err, hash){
    //     const newUser = new User({
    //         email: req.body.username,
    //         password: hash
    //     });
    
    //     newUser.save().then(() => {
    //         res.render("secrets");
    //     }).catch((err) => {
    //         console.log(err);
    //     });
    // });


    //Level 5
    // User.register({email: req.body.username}, req.body.password, function(err, user){
    //     if(err)
    //     {
    //         console.log(err);
    //         res.redirect("/register");
    //     }
    //     else
    //     {
    //         passport.authenticate("local")(req, res, function(){
    //             res.redirect("/secrets");
    //         });
    //     };
    // });

    User.register({username: req.body.username}, req.body.password).then(() => {
        passport.authenticate("local")(req, res, () => { 
            res.redirect("/secrets");
        });
    }).catch((err) => {
        console.log(err);
        res.redirect("/register");
    });
});


app.post("/login", function(req,res){
    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({email: username}).then((found_user) => {
    //     bcrypt.compare(password, found_user.password, function(err, result){
    //         if(result === true){
    //             res.render("secrets");
    //         };
    //     });
        
    // }).catch((err) => {
    //     console.log(err);
    // });


    //Level 5
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err){
        if(err){
            console.log(err);
        }
        else{
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        };
    });

    // req.login(user).then(() => {
    //     passport.authenticate("local")(req, res, () => {
    //         res.redirect("/secrets");
    //     });
    // }).catch((err) => {
    //     console.log(err);
    // });
});















/////Port connection
const port = process.env.PORT || 3000;
app.listen(port, function(req,res){
    console.log("Server started.");
});



/* 
secrets.ejs cut code
line 8
<!-- <% usersWithSecrets.forEach(function(user){ %>
      <p class="secret-text"><%=user.secret%></p>
    <% }) %> -->
callbackURL: "http://0.0.0.0/auth/google/secrets",

*/
