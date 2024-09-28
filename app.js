require('dotenv').config();
const express=require("express")
const bodyParser=require("body-parser")
const ejs =require("ejs")
const mongoose=require("mongoose")
const session = require('express-session')
const passport=require("passport")
const passportLocalMongoose=require("passport-local-mongoose")
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy=require("passport-facebook").Strategy
const findOrCreate = require('mongoose-find-or-create')


// const encrypt=require("mongoose-encryption")
// var md5 = require('md5');
// const bcrypt = require('bcrypt');
// const saltRounds = 10;

const app=express();


app.use(bodyParser.urlencoded({extended:true}));
app.set("view engine","ejs");

app.use(express.static("Public"))



app.use(session({
    secret:"Our little secret.",
    resave:false,
    saveUninitialized:false
}));

app.use(passport.initialize())
app.use(passport.session())



mongoose.connect("mongodb://localhost:27017/userDB");



const userSchema=new mongoose.Schema({
    email:String,
    password:String,
    googleId:String,
    facebookId:String,
    secret:String
})  

userSchema.plugin(passportLocalMongoose)
userSchema.plugin(findOrCreate)



const User=new mongoose.model("user",userSchema);

passport.use(User.createStrategy());

// use static serialize and deserialize of model for passport session support
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });

passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get("/",function(req,res){
    res.render("home");
})

app.get("/auth/google",
    passport.authenticate("google", {scope:["profile"]})
)

app.get('/auth/google/secrets', 
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
      // Successful authentication, redirect home.
      res.redirect('/secrets');
    });

    app.get('/auth/facebook',
        passport.authenticate('facebook'));
      
      app.get('/auth/facebook/secrets',
        passport.authenticate('facebook', { failureRedirect: '/login' }),
        function(req, res) {
          // Successful authentication, redirect home.
          res.redirect('/secrets');
        });


app.get("/login",function(req,res){
    res.render("login");
})


app.get("/secrets",function(req,res){
    User.find({ secret: { $ne: null }})
    .then((foundUsers)=>{
        if (foundUsers){
            res.render("secrets",{usersWithSecrets:foundUsers})
        }
    })
    .catch(err=>{
        console.log(err)
    })

})

app.get("/submit",function(req,res){
    if (req.isAuthenticated()){
        console.log()
        res.render("submit")
    }else{
        res.redirect("/login")
    } 
})

app.post("/submit",function(req,res){
    const submittedSecret=req.body.secret
    console.log(req.user.id)
    User.findById(req.user.id)
    .then((foundUser)=>{
        if(foundUser){
            foundUser.secret=submittedSecret
            foundUser.save()
            res.redirect("/secrets")
        }})
    .catch(err=>{
        console.log(err)
    })
})

app.get("/register",function(req,res){
    res.render("register")
})

app.post("/register", function (req, res) {
    User.register({username: req.body.username}, req.body.password)
        .then(() => {
            passport.authenticate("local")(req, res, function () {
                res.redirect("/secrets");
            });
        })
        .catch(err => {
            console.log(err);
            res.redirect('/register');
        });
});

app.post("/login", passport.authenticate('local', {
    successRedirect: '/secrets',
    failureRedirect: '/login'
}));

app.get("/logout",function(req,res){
    req.logout(function(){
       res.redirect("/") 
    })
    
})













app.listen(3000,function(){
    console.log("Server is running on port 3000")
})