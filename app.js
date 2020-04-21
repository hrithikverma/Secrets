//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyparser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const passport = require("passport");
const passportlocalmongoose = require("passport-local-mongoose");
const session = require("express-session");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();
// const bcrypt = require("bcrypt");
// const md5 = require("md5");
// const encrypt = require("mongoose-encryption");
app.use(session({
  secret : "hrithik verma",
  resave : false,
  saveUninitialized : false
}));
mongoose.connect("mongodb://localhost:27017/userDB",{useNewUrlParser: true, useUnifiedTopology: true});
app.use(bodyparser.urlencoded({
  extended : true
}));
app.use(express.static("public"));
app.set("view engine","ejs");
app.use(passport.initialize());
app.use(passport.session());
const UserSchema = new mongoose.Schema({
  username : String,
  password : String,
  googleId : String,
  usersecret : String
});
UserSchema.plugin(passportlocalmongoose);
UserSchema.plugin(findOrCreate);
// UserSchema.plugin(encrypt,{secret : process.env.SECRET , encryptedFields : ["password"]});
const User = mongoose.model("User",UserSchema);
passport.use(User.createStrategy());
passport.serializeUser(function(user, done) {
  done(null, user.id);
});
passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    // console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

app.listen(3000,()=>{
  console.log("server started at port 3000");
});
app.get("/",(req,res)=>{
  res.render("home");
});
app.get("/login",(req,res)=>{
  res.render("login");
});
app.get("/register",(req,res)=>{
  res.render("register");
});
app.get("/submit",(req,res)=>{
   if(req.isAuthenticated()){
     res.render("submit");
   }else{
     res.redirect("/login");
   }
});
app.post("/submit",(req,res)=>{
  const mysecret = req.body.secret;
  User.update({_id : req.user._id},{$set : {usersecret : mysecret}},(err)=>{
    if(err) console.log(err);
    else res.redirect("/secrets");
  });
});

//USING PASSPORT
app.get("/secrets",(req,res)=>{
  // console.log(req.isAuthenticated());
  if(req.isAuthenticated()){
    User.find({usersecret : {$ne : null}},(err,foundarr)=>{
      if(err){
        console.log(err);
      }else{
        res.render("secrets",{userarray : foundarr});
      }
    });
  }
  else
  res.redirect("/");
});
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }));

app.get("/auth/google/secrets",
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect("/secrets");
});

app.post("/register",(req,res)=>{
  User.register({username: req.body.username},req.body.password,(err,user)=>{
    if(err){
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req,res,()=>{
        res.redirect("/secrets");
      });
    }
  });
});
app.post("/login",(req,res)=>{
    const user = new User({
      username : req.body.username,
      password : req.body.password
    });
    req.login(user,(err)=>{
      if(err){
        res.redirect("/login");
      }else{
        passport.authenticate("local")(req,res,()=>{
          res.redirect("/secrets");
        });
      }
    });
});
app.get("/logout",(req,res)=>{
  req.logout();
  res.redirect("/");
});

// USING bcrypt
/*
app.post("/login",(req,res)=>{

  User.findOne({username : req.body.username},(err,founduser)=>{
    if(err){
      res.send(err);
    }else{
      if(founduser){
        bcrypt.compare(req.body.password, founduser.password, function(err, result) {
          if(result){
            res.render("secrets");
          }else{
            res.send("<h1>Username and Password do not match</h1>");
          }
        });
      }else{
        res.send("<h1>Please Register</h1>");
      }
    }
  });
});
app.post("/register",(req,res)=>{

bcrypt.hash(req.body.password,10, function(err, hash) {
  const newuser = new User({
    username : req.body.username,
    password : hash
  });
  newuser.save((err)=>{
    if(!err){
      res.render("secrets");
    }
  });
});
});
*/
