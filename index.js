require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const Joi = require('joi');


const expireTime = 1 * 60 * 60 * 1000; //expires after 1 hour  (hours * minutes * seconds * millis)

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;

const node_session_secret = process.env.NODE_SESSION_SECRET;
/* END secret section */

var {database} = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({ 
    secret: node_session_secret,
	store: mongoStore, //default is memory store 
	saveUninitialized: false, 
	resave: true
}
));

app.get('/', (req,res) => {
   
    if (req.session.authenticated) {
        var html = `<p>Hello, ${req.session.name}!</p>
            <form action='/members' method='get'>
            <button>Go to Members Area</button>
            </form>
            <form action='/logout' method='get'>
            <button>Log out</button>
            </form>`;
    } else {
        var html = `
        <form action='/signup' method='get'>
        <button>Sign up</button>
        </form>
        <form action='/login' method='get'>
        <button>Log in</button>
        </form>
        `;
    }
    res.send(html); 
});

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});



app.get('/signup', (req,res) => {
    var html = `
    create user
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});


app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='username' type='text' placeholder='username'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.object(
		{
            name: Joi.string().max(20).required(),
			username: Joi.string().alphanum().max(20).required(),
			password: Joi.string().max(20).required()
		});
	
	const validationResult = schema.validate({name, username, password});
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.send('<form action="/signup" method="get">Try again</form>');
	   return;
   }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
	
	await userCollection.insertOne({name: name, username: username, password: hashedPassword});
	console.log("Inserted user");

    var html = "successfully created user";
    res.send(html);
    res.redirect("/members");
});

app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("Invalid email/password combination");
		res.send('<form action="/login" method="get">Try again</form>');
		return;
	}
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    var randomCatID = Math.floor(Math.random() * 3) + 1;
    var cat;
    if (randomCatID == 1) {
        cat = "Fluffy: <img src='/fluffy.gif' style='width:250px;'>";
    }
    else if (randomCatID == 2) {
        cat = "Socks: <img src='/socks.gif' style='width:250px;'>";
    }
    else {
        cat = "Trumpet: <img src='/trumpet.gif' style='width:250px;'>";
    }  

    var html = `
     <h1>Hello, ${req.session.name}.</h1>
        <h2>Welcome to the members area.</h2>
        <h2>Here is a random cat for you:</h2>
        <h2>${cat}</h2>
        <form action='/logout' method='get'>
        <button>Log out</button>
        </form>
    `;
    res.send(html);
});



app.get('/logout', (req,res) => {
	req.session.destroy();
    var html = `
    You are logged out.
    `;
    res.send(html);
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 