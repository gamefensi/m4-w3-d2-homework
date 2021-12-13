const express = require('express'),
    app = express(),
    mongoose = require("mongoose"),
    passport = require("passport"),
    bodyParser = require("body-parser"),
    LocalStrategy = require("passport-local"),
    passportLocalMongoose = require("passport-local-mongoose"),
    User = require("./models/user"),
    mongoSanitize = require('express-mongo-sanitize'),
    rateLimit = require('express-rate-limit'),
    xss = require('xss-clean'),
    helmet = require('helmet'),
    { check, validationResult } = require('express-validator');

//Connecting database
mongoose.connect("mongodb://localhost/auth_demo");

const expSession = require("express-session")({
    secret: "mysecret",       //decode or encode session
    resave: false,
    saveUninitialized: true,
    cookie: {
        httpOnly: true,
        secure: true,
        maxAge: 1 * 60 * 1000 // 10 minutes
    }
});

passport.serializeUser(User.serializeUser());       //session encoding
passport.deserializeUser(User.deserializeUser());   //session decoding
passport.use(new LocalStrategy(User.authenticate()));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded(
    { extended: true }
))
app.use(passport.initialize());
// app.use(passport.session());
app.use(expSession);
app.use(express.static("public"));


//=======================
//      O W A S P
//=======================
//Data Sanitization against NoSQL Injection Attacks
app.use(mongoSanitize());
//Preventing Brute Force & DOS Attacks - Rate Limiting
const limit = rateLimit({
    max: 100,// max requests
    windowMs: 60 * 60 * 1000, // 1 Hour of 'ban' / lockout
    message: 'Too many requests' // message to send
});
app.use('/routeName', limit); // Setting limiter on specific route
//Preventing DOS Attacks - Body Parser
app.use(express.json({ limit: '10kb' })); // Body limit is 10
//Data Sanitization against XSS attacks
app.use(xss());
//Helmet to secure connection and data
app.use(helmet.contentSecurityPolicy({
    useDefaults: true,
    directives: {
        "script-src": ["'self'","code.jquery.com","cdnjs.cloudflare.com","bootstrapcdn.com"],
        "script-src-elem": ["'self'","code.jquery.com","cdnjs.cloudflare.com","stackpath.bootstrapcdn.com"]
    }
}));

//=======================
//      R O U T E S
//=======================
app.get("/", (req, res) => {
    res.render("home");
})
app.get("/userprofile", (req, res) => {
    res.render("userprofile");
})
//Auth Routes
app.get("/login", (req, res) => {
    res.render("login");
});
app.post("/login", passport.authenticate("local", {
    successRedirect: "/userprofile",
    failureRedirect: "/login"
}), function (req, res) {
});
app.get("/register", (req, res) => {
    res.render("register");
});

app.post("/register",
    [
        check('username')
        .isLength({ min: 3 })
        .withMessage('Username must be at least 3 characters long'),
        check('password')
        .matches(/^(?=.*\d)(?=.*[a-z])(?=.*[A-Z])[0-9a-zA-Z]{8,}$/, "i")
        .withMessage('Password must use a minimum eight characters, at least one letter and one number')
    ],
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            res.render('register', { 
                title: 'Registration page',
                errors: errors.array(),
                data: req.body,
             });
        } else {
        User.register(
            new User({
                username: req.body.username,
                email: req.body.email,
                phone: req.body.phone
            }),
            req.body.password, function (err, user) {
                if (err) {
                    console.log(err);
                    res.render("register");
                }
                passport.authenticate("local")(req, res, function () {
                    res.redirect("/login");
                })
            }
        )
    }
})
app.get("/logout", (req, res) => {
    req.logout();
    res.redirect("/");
});
function isLoggedIn(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect("/login");
}

//Listen On Server
app.listen(process.env.PORT || 3000, function (err) {
    if (err) {
        console.log(err);
    } else {
        console.log("Server Started At Port 3000");
    }
});