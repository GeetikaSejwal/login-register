const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const passport = require('passport')

//User Model
const User = require('../models/User')
//Login Page
router.get('/login', (req, res) => res.render('login'));

//register Page
router.get('/register', (req, res) => res.render('register'));

//Register Handle
router.post('/register', (req, res) => {
    const { name, email, password, password2 } = req.body;
    let errors = [];

    //check required feilds
    if (!name || !email || !password || !password2) {
        errors.push({ msg: 'please fill all fields' });
    }
    //check passwrd check
    if (password !== password2) {
        errors.push({ msg: 'Passwords do not match' });
    }
    //check password length
    if (password.length < 6) {
        errors.push({ msg: 'password should be at least 6 characters' });
    }
    
    if (errors.length > 0) {
        res.render('register', {
            errors,
            name,
            email,
            password,
            password2
        });
    } else {
        // validation passed
        User.findOne({ email: email })
            .then(user => {
                if (user) {
                    //User exists
                    errors.push({msg: 'Email exists'})
                    res.render('register', {
                    errors,
                    name,
                    email,
                    password,
                    password2
                });
                } else {
                    const newUser = new User({
                        name,
                        email,
                        password
                    });

                    //hash password
                    bcrypt.genSalt(10, (err, salt) => bcrypt.hash(newUser.password, salt, (err,hash) => {
                        if (err) throw err;
                        //set password to hash
                        newUser.password = hash;
                        //save user
                        newUser.save()
                            .then(user => {
                                req.flash('success_msg', 'you are now registered');
                                res.redirect('/users/login');
                            })
                            .catch(err => console.log(err));
                    }))
                }
            });
    }
    
});

//login handle
router.post('/login', (req, res, next) => {
    passport.authenticate('local', {
        successRedirect: '/dashboard',
        failureRedirect: '/users/login',
        failureFlash: true
    })(req, res, next);
});
//logout handle
router.get('/logout', (req, res) => {
    req.logout();
    req.flash("success_msg", "logout successfully");
    res.redirect('/users/login');
})
module.exports = router;