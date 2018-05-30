var express = require('express');
var bodyParser = require('body-parser');
var app = express();
var session = require('express-session');
var bcrypt = require('bcryptjs');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
var cors = require('cors');

var jwt = require('jsonwebtoken');
var expressjwt = require('express-jwt');

var passportJWT = require("passport-jwt");
var ExtractJwt = passportJWT.ExtractJwt;
var JwtStrategy = passportJWT.Strategy;

var mysql      = require('mysql');
var pool = mysql.createPool({
    host     : ,
    user     : ,
    password : ,
    database : 
});

const saltRounds = 10;
const secret = 'nayeijnix';

let whitelist = ['http://example.com', 'http://www.example.com'];

let corsOptions = {
    origin: function (origin, callback) {
	if (whitelist.indexOf(origin) !== -1) {
	    callback(null, true)
	} else {
	    console.log(origin);
	    callback(new Error('Not allowed.'))
	}
    },
    optionsSuccessStatus: 200
}

app.use(cors(corsOptions));
app.use(bodyParser.json());


// passport.use(new LocalStrategy({
//     usernameField: 'email',
//     passwordField: 'password',
//     passReqToCallback: true,
//     session: false
// }, function(req, email, password, done) {
//     connection.query({
// 	sql: 'select password, idluser from `user_account` where idluser=(select iduser from`user_profile` where email=?)',
// 	values: [req.body.email]
//     }, function (error, results) {
// 	if (error) {
// 	    return done(error);
// 	};
// 	if (!results.length) {
// 	    console.log('User not found');
// 	    return done(null, false)
// 	}
// 	if (results.length) {
// 	    bcrypt.compare(req.body.password, results[0].password)
// 		.then((response) => {
// 		    if (response === false) {
// 			console.log('Password incorrect');
// 			return done(null, false);
// 		    }
// 		    if (response === true) {
// 			console.log('Password correct');
// 			console.log(JSON.stringify(results[0]));
// 			var token = jwt.sign({'iduser': results[0].idluser.toString()}, secret, {
// 			    expiresIn: '120'
// 			});
// 			console.log(token);
// 			// return done(null, token)
// 			return done(null, results[0]);
// 		    }
// 		})
// 		.catch((err) => {
// 		    console.log(err);
// 		});
// 	}
//     });
// }))

// app.use(passport.initialize());
// app.use(passport.session());

app.get('/', function(req, res) {
    res.send('Hello, World!')
})

app.get('/users/:id',
	expressjwt({secret: secret}),
	function(req, res) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'select * from `user_profile` where `iduser`=?',
		    values:[req.params.id]
		}, function (error, results, fields) {
		    connection.release();
		    console.log('The solution is: ', results);
		    res.send(results)
		    if (error) throw error;
		});
	    });
	});

app.post('/signup', function(req, res) {
    pool.getConnection(function(err, connection) {
	connection.query({
	    sql: 'insert into `user_profile` (email, firstname, lastname, createdat) values (?, ?, ?, ?)',
	    values: [req.body.email, req.body.firstname, req.body.lastname, req.body.createdat]
	}, function (error, results) {
	    connection.release();
	    if (error) throw error;
	    console.log('The solution is: ', results);
	});
    });
    
    bcrypt.genSalt(saltRounds, function(err, salt) {
	bcrypt.hash(req.body.password, salt, function(err, hash) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'insert into `user_account` (idluser, password, password_salt, hash_algorithm) values ((select iduser from `user_profile` where email=?), ?, ?, ?)',
		    values: [req.body.email, hash, salt, 'bcrypt']
		}, function (error, results) {
		    connection.release();
		    if (error) throw error;
		});
	    });
	});
    });
})

app.post('/signin', function(req, res) {
    pool.getConnection(function(err, connection) {
	connection.query({
	    sql: 'select password, idluser from `user_account` where idluser=(select iduser from`user_profile` where email=?)',
	    values: [req.body.email]
	}, function (error, results, fields) {
	    connection.release();
	    if (error) throw error;
	    bcrypt.compare(req.body.password, results[0].password)
		.then((response) => {
		    if (response === false) {
			console.log('Password incorrect');
			res.send({success:false});
		    } else {
			console.log('Password correct');
			console.log(JSON.stringify(results[0]));
			var token = jwt.sign(
			    {
				'iduser': results[0].idluser.toString()
			    },
			    secret,
			    {
				expiresIn: '10h'
			    }
			);
			res.send({success: true, token: 'JWT ' + token})
		    }
		})
		.catch((err) => {
		    console.log(err);
		});
	});
    });
})

app.get('/check',
	expressjwt({secret: secret}),
	function(req, res) {
	    console.log(req.user);
	    res.send({success: true});
})

app.post('/list/new',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection) {
		 connection.query({
		     sql: 'insert into `tasklist` (listname, createdby, createdat, refid) values (?, ?, ?, ?)',
		     values: [req.body.listname, req.user.iduser, req.body.createdat, req.body.ind]
		 }, function (error, results) {
		     connection.release();
		     if (error) throw error;
		     res.send({success: true});
		 });
	     });
	 })

app.post('/task/delete',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection) {
		 connection.query({
		     sql: 'update tasks set deleted=1 where refid=(?)',
		     values: [req.body.taskid]
		 }, function (error, results) {
		     connection.release();
		     if (error) throw error;
		     res.send({success: true});
		 });
	     });
	 })

app.post('/task/toggle',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection) {
		 connection.query({
		     sql: 'update tasks set `done`=NOT `done` where refid=(?)',
		     values: [req.body.taskid]
		 }, function (error, results) {
		     connection.release();
		     if (error) throw error;
		     res.send({success: true});
		 });
	     });
	 })

app.get('/user/lists',
	expressjwt({secret: secret}),
	function(req, res) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'select listname, refid from `tasklist` where createdby=(?)',
		    values: [req.user.iduser]
		}, function (error, results) {
		    if (error) {
			throw error;
		    };
		    console.log('The solution is: ', results);
		    res.send({success: true, results: results});
		});
	    });
	})

app.get('/list/latest',
	expressjwt({secret: secret}),
	function(req, res) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'select idtasklist, listname from `tasklist` where createdby=(?) order by idtasklist desc limit 1',
		    values: [req.user.iduser]
		}, function (error, results) {
		    connection.release();
		    if (error) throw error;
		    console.log('The solution is: ', results);
		    res.send({success: true, results: results});
		});
	    });
	})

app.get('/user/sharedlists',
	expressjwt({secret: secret}),
	function(req, res) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'select listname, refid from `tasklist` join `listview` on tasklist.idtasklist=listview.idtasklist and listview.userid=(?)',
		    values: [req.user.iduser]
		}, function (error, results) {
		    connection.release();
		    if (error) throw error;
		    console.log('The solution is: ', results);
		    res.send({success: true, results: results});
		});
	    });
	})


app.post('/new/task',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection) {
		 connection.query({
		     sql: 'insert into `tasks` (task, createdby, createdat, assignee, tasklist, refid) select ?, ?, ?, ?, idtasklist, ? from tasklist where refid=(?)',
		     values: [req.body.task, req.user.iduser, req.body.createdat, req.user.iduser, req.body.refid, req.body.reftasklist]
		 }, function (error, results) {
		     connection.release();
		     if (error) throw error;
		     console.log('The solution is: ', results);
		     res.send({success: true});
		 });
	     });
	 })

app.post('/task/edit',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection){
		 connection.query({
		     sql: 'update tasks set task=(?) where refid=(?)',
		     values: [req.body.editedtask, req.body.taskid]
		 }, function (error, results) {
		     connection.release();
		     if (error) throw error;
		     res.send({success: true});
		 });
	     });
	 })

app.get('/list/:listid',
	expressjwt({secret: secret}),
	function(req, res) {
	    pool.getConnection(function(err, connection) {
		connection.query({
		    sql: 'select refid as id, task, createdby, done, createdat from `tasks` where tasklist=(select idtasklist from tasklist where refid=(?)) and deleted=0',
		    values: [req.params.listid]
		}, function (error, results) {
		    connection.release();
		    if (error) throw error;
		    console.log('The solution is: ', results);
		    res.send({success: true, results: results});
		});
	    });
	})

app.post('/list/:refid/share',
	 expressjwt({secret: secret}),
	 function(req, res) {
	     pool.getConnection(function(err, connection){
		 connection.query({
		     sql: 'select createdby, idtasklist from tasklist where refid=(?)',
		     values: [req.params.refid]
		 }, function (error, results) {
		     if (error) throw error;
		     console.log('No error.', results);
		     console.log(results[0].createdby.toString() === req.user.iduser.toString());
		     console.log(results[0].idtasklist);
		     if ( results[0].createdby.toString() === req.user.iduser.toString() ) {
			 connection.query({
			     sql: 'insert into listview (userid, idtasklist) select iduser, (?) from user_profile where email=(?)',
			     values: [results[0].idtasklist, req.body.shareuser]
			 }, function (error, moresults) {
			     connection.release();
			     if (error) throw error;
			     console.log('No error.', results);
			     res.send({success: true});
			 });
		     } else {
			 console.log('User cannot share this list.')
			 res.send({success: false});
		     }
		 });
	     });
	 })

app.listen('3000');
