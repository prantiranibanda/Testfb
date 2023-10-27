//jshint esversion:6
import dotenv from'dotenv';
import express from 'express';
import mongoose from 'mongoose';
import bodyParser from 'body-parser';
import { Schema } from 'mongoose';
//import bcrypt from 'bcrypt';
import session from 'express-session';
import passport from 'passport';
import passportLocalMongoose from 'passport-local-mongoose';
import GoogleS from 'passport-google-oauth20';
import findOrCreate from 'mongoose-findorcreate';

import ejs from 'ejs';

//const env = dotenv.config();
const app = express();
const port = 3000;
//const saltRounds = 10;
const GoogleStrategy = GoogleS.Strategy;

app.use(express.static("public"));
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended: true}));

app.use(session({
    secret: "our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());


mongoose.connect("mongodb://127.0.0.1:27017/userDB");

const userSchema = new Schema({
    username: String,
    password: String,
    googleId: String
});

userSchema.plugin(passportLocalMongoose); ////////
userSchema.plugin(findOrCreate);

const User = new mongoose.model('User', userSchema);

passport.use(User.createStrategy());

// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id).then((user) => {
    done(null, user);
  })
  .catch((error) => {
    console.log(`Error: ${error}`);
  });
});

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

app.get("/", (req, res)=>{
    res.render("home");
});

app.get('/auth/google', 
    passport.authenticate('google', { scope: ['profile'] })
);
app.get('/auth/google/secrets', passport.authenticate('google', { failureRedirect: '/login' }), 
    (req, res)=>{
        res.redirect("/secrets");
    });

app.get("/login", (req, res)=>{
    res.render("login");
});

app.get("/register", (req, res)=>{
    res.render("register");
});

app.get("/secrets", (req, res)=>{
    if(req.isAuthenticated()){
        res.render("secrets");
    }else{
        res.redirect("/login");
    }
});

app.get("/logout", (req, res)=>{
    req.logout((err)=>{
        if (err) { return next(err); }
        res.redirect('/');
    });
});


app.post("/register", (req, res)=>{

    User.register({username: req.body.username}, req.body.password, (err, user)=>{
        if(err){
            console.log(err);
            res.redirect("/register");
        }else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    });



    // bcrypt.hash(req.body.password, saltRounds, (err, hash)=>{
    //    const newUser = new User({
    //     username: req.body.username,
    //     password: hash
    //     });

    //     newUser.save().then(()=>{
    //         res.render("secret");
    //     }).catch((err)=>{
    //         console.log(err);
    //     }); 
    // });
});

app.post("/login", (req,res)=>{

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, (err)=>{
        if(err){
            console.log(err);
        }else{
            passport.authenticate("local")(req, res, ()=>{
                res.redirect("/secrets");
            });
        }
    })

    // const username = req.body.username;
    // const password = req.body.password;

    // User.findOne({username: username}).then((docs)=>{
        
    //     bcrypt.compare(password, docs.password, (err, result)=>{
    //         if(result === true){
    //             res.render("secret"); //123456 1234
    //         }
    //     })        
    // }).catch((err)=>{
    //     console.log(err);   
    // })
});

app.listen(port, ()=>{
    console.log(`Listening on the port ${port}`);
});