require("./utils.js");

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const Joi = require('joi');

const port = process.env.PORT || 3300;
const expireTime = 1 * 60 * 60 * 1000; // 1 hour

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const app = express();
app.use(express.urlencoded({extended: false}));

var {database} = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: { secret: mongodb_session_secret }
});

app.use(session({
    secret: node_session_secret,
	store: mongoStore,
	saveUninitialized: false,
	resave: true
}));


// Connect to MongoDB
(async () => {
    try {
        await database.connect();
        console.log("Connected to MongoDB Atlas");
    } catch (err) {
        console.error("Failed to connect to MongoDB", err);
    }
})();

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
        </form>`;
    }
    res.send(html);
});

app.get('/nosql-injection', async (req, res) => {
	var email = req.query.email;

	if (!email) {
		res.send(`<h3>No email provided - try /nosql-injection?email=test@example.com</h3><h3>or /nosql-injection?email[$ne]=test@example.com</h3>`);
		return;
	}
	console.log("email: " + email);

	const schema = Joi.string().email().max(40).required();
	const validationResult = schema.validate(email);

	if (validationResult.error != null) {
		console.log(validationResult.error);
		res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
		return;
	}

	const result = await userCollection.find({email: email}).project({name: 1, email: 1, _id: 1}).toArray();

	console.log(result);
	res.send(`<h1>Hello ${email}</h1>`);
});


app.get('/signup', (req,res) => {
    var html = `
    Create user:
    <form action='/submitUser' method='post'>
    <input name='name' type='text' placeholder='name'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>`;
    res.send(html);
});

app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        res.send("Invalid input: " + validationResult.error.details[0].message + `<form action="/signup" method="get"><button>Try again</button></form>`);
        return;
    }

    const existingUser = await userCollection.findOne({email: email});
    if (existingUser) {
        res.send("This email is already registered. <form action='/signup' method='get'><button>Try again</button></form>");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    res.redirect("/members");
});

app.get('/login', (req,res) => {
    var html = `
    Log in:
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>`;
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object({
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({email, password});
    if (validationResult.error != null) {
        res.send("Invalid input. <form action='/login' method='get'><button>Try again</button></form>");
        return;
    }

    const result = await userCollection.find({email: email}).project({name: 1, email: 1, password: 1}).toArray();
    if (result.length != 1) {
        res.send("Email not found. <form action='/login' method='get'><button>Try again</button></form>");
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = email;
        req.session.cookie.maxAge = expireTime;
        res.redirect('/members');
        return;
    } else {
        res.send("Invalid email/password combination. <form action='/login' method='get'><button>Try again</button></form>");
        return;
    }
});

app.get('/members', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
        return;
    }

    var randomCatID = Math.floor(Math.random() * 3) + 1;
    var cat;
    if (randomCatID == 1) {
        cat = "Fluffy: <img src='/fluffy.gif' style='width:250px;'>";
    } else if (randomCatID == 2) {
        cat = "Socks: <img src='/socks.gif' style='width:250px;'>";
    } else {
        cat = "Trumpet: <img src='/trumpet.gif' style='width:250px;'>";
    }

    var html = `
    <h1>Hello, ${req.session.name}.</h1>
    <h2>Welcome to the members area.</h2>
    <h2>Here is a random cat for you:</h2>
    <h2>${cat}</h2>
    <form action='/logout' method='get'>
    <button>Log out</button>
    </form>`;
    res.send(html);
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.send("You are logged out. <a href='/'>Go home</a>");
});

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
    res.status(404);
    res.send("Page not found - 404");
});

app.listen(port, () => {
    console.log("Node application listening on port "+port);
});
