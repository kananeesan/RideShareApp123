// config/passport.js

// load all the things we need
var LocalStrategy = require('passport-local').Strategy;


var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var dbconfig = require('../config/database');
var connection = mysql.createConnection(dbconfig.connection);

connection.query('USE ' + dbconfig.database);


module.exports = function (userModel) {
    
    // =========================================================================
    // passport session setup ==================================================
    // =========================================================================
	

    // used to serialize the user for the session
	userModel.serializeUser(function (user, done) {
        done(null, user.id);
    });
    
    // used to deserialize the user
	userModel.deserializeUser(function (id, done) {
        connection.query("SELECT * FROM usernew WHERE id = ? ", [id], function (err, rows) {
            done(err, rows[0]);
        });
    });
    
    // =========================================================================
    // LOCAL SIGNUP ============================================================
    // =========================================================================
	userModel.use(
        'local-signup',
        new LocalStrategy({
            usernameField : 'username',
            passwordField : 'password',
            passReqToCallback : true // allows us to pass back the entire request to the callback
        },
        function (req, username, password, done) {
            // find a user whose username is the same as the forms username
            // we are checking to see if the user trying to login already exists
            connection.query("SELECT * FROM usernew WHERE username = ?", [username], function (err, rows) {
                if (err)
                    return done(err);
                if (rows.length) {
                    return done(null, false, req.flash('signupMessage', 'That username is already taken.'));
                } else {
                    // if there is no user with that username
                    // create the user
                    var newUserMysql = {
                        fname: req.param('fname'),
                        lname: req.param('lname'),
                        username: username,
                        email: req.param('email'),
                        password: bcrypt.hashSync(password, null, null)
                        // use the generateHash function in our user model
                    };
                    
                    var insertQuery = "INSERT INTO usernew ( fname, lname, username, email, password ) values (?,?,?,?,?)";
                    
                    connection.query(insertQuery, [newUserMysql.fname, newUserMysql.lname, newUserMysql.username, newUserMysql.email, newUserMysql.password], function (err, rows) {
                        newUserMysql.id = rows.insertId;
                        
                        return done(null, newUserMysql);
                    });
                }
            });
        })
    );
    
    // =========================================================================
    // LOCAL LOGIN =============================================================
    // =========================================================================
	userModel.use(
        'local-login',
        new LocalStrategy({
            // local strategy uses username and password
            usernameField : 'username',
            passwordField : 'password',
            passReqToCallback : true // allows us to pass back the entire request to the callback
        },
        function (req, username, password, done) { // callback with email and password from our form
            connection.query("SELECT * FROM usernew WHERE username = ?", [username], function (err, rows) {
                if (err)
                    return done(err);
                if (!rows.length) {
                    return done(null, false, req.flash('loginMessage', 'No user found.')); // req.flash is the way to set flashdata using connect-flash
                }
                
                // if the user is found but the password is wrong
                if (!bcrypt.compareSync(password, rows[0].password))
                    return done(null, false, req.flash('loginMessage', 'You Entered The Wrong password.')); // create the loginMessage and save it to session as flashdata
                
                // return successful user
                return done(null, rows[0]);
            });
		}
		
		
		)
	);

	
	

};


