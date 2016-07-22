// Controller/routes.js

var geohash = require("geohash").GeoHash;
var dbconfig = require("../config/database");
var mysql = require("mysql");
var bcrypt = require('bcrypt-nodejs');
var LocalStrategy = require('passport-local').Strategy;
var connection = mysql.createConnection(dbconfig.connection);
connection.query('USE ' + dbconfig.database);

module.exports = function (app, userModel) {
	
	// =====================================
	// HOME PAGE  ========
	// =====================================
	app.get('/', function (req, res) {
		res.render('index.ejs'); // load the index.ejs file
		
	});
	
	
	
	// =====================================
	// LOGIN ===============================
	// =====================================
	// show the login form
	app.get('/login', function (req, res) {
		
		// render the page and pass in any flash data if it exists
		res.render('login.ejs', { message: req.flash('loginMessage') });
	});
	
	
	// process the login form
	app.post('/login', userModel.authenticate('local-login', {
		successRedirect : '/profile', // redirect to the secure profile section
		failureRedirect : '/login', // redirect back to the signup page if there is an error
		failureFlash : true // allow flash messages
	}),
        function (req, res) {
		console.log("hello");
		
		if (req.body.remember) {
			req.session.cookie.maxAge = 1000 * 60 * 3;
		} else {
			req.session.cookie.expires = false;
		}
		res.redirect('/');
	});
	
	
	
	
	// =====================================
	// SIGNUP ==============================
	// =====================================
	// show the signup form
	app.get('/signup', function (req, res) {
		// render the page and pass in any flash data if it exists
		res.render('signup.ejs', { message: req.flash('signupMessage') });
	});
	
	// process the signup form
	app.post('/signup', userModel.authenticate('local-signup', {
		successRedirect : '/profile', // redirect to the secure profile section
		failureRedirect : '/signup', // redirect back to the signup page if there is an error
		failureFlash : true // allow flash messages
	}));
	

	////////////////////////////////////////
	////////////////edit profile///////////
	
	app.get('/edit', isLoggedIn, function (req, res) {
		
		
		
		connection.query("SELECT * FROM usernew WHERE username = ?", req.user.username , function (err, rows) {
			
			
			console.log(rows[0]);
			
			res.render('edit.ejs', { userDetails : rows, user : req.user });
		});
		
		
		
		
	});
	
	
	// =====================================
	// LOGOUT ==============================
	// =====================================
	app.get('/logout', function (req, res) {
		req.logout();
		res.redirect('/');
	});
	
	
	//////////////////
	//process the update form
	app.post('/update', function (req, res) {
		
		
		var newUserMysql = {
			fname: req.param('fname'),
			lname: req.param('lname'),
			username: req.param('username'),
			email: req.param('email'),
			password: bcrypt.hashSync(req.param('password'), null, null)
            // use the generateHash function in our user model
		};
		
		var updateQuery = "UPDATE usernew SET fname = ?, lname = ?, username = ? , email = ? , password = ? where id = ?";
		connection.query(updateQuery, [newUserMysql.fname, newUserMysql.lname, newUserMysql.username, newUserMysql.email, newUserMysql.password, req.user.id]);
		
		res.redirect('/');
	});

};


// =====================================
// PROFILE SECTION =========================
// =====================================
// we will want this protected so you have to be logged in to visit
// we will use route middleware to verify this (the isLoggedIn function)
module.exports.getAllDrivers = function (req, res) {
	
	
		connection.query('SELECT * FROM vehicle', function (err, rows) {
		if (err) throw err;
		
		console.log('Data received from Db:\n');
		
		console.log(rows);
		res.json(rows);
			
	});
		
		
};



// route middleware to make sure
function isLoggedIn(req, res, next) {
	
	// if user is authenticated in the session, carry on
	if (req.isAuthenticated())
		return next();
	
	// if they aren't redirect them to the home page
	res.redirect('/');
}






