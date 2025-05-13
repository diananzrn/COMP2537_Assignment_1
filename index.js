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

app.set('view engine', 'ejs');

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

function isValidSession(req) {
    if (req.session.authenticated) {
        return true;
    }
    return false;
}

function sessionValidation(req,res,next) {
    if (isValidSession(req)) {
        next();
    }
    else {
        res.redirect('/login');
    }
}


function isAdmin(req) {
    if (req.session.user_type == 'admin') {
        return true;
    }
    return false;
}

function adminAuthorization(req, res, next) {
    if (!isAdmin(req)) {
        res.status(403);
        res.render("errorMessage", {error: "Not Authorized"});
        return;
    }
    else {
        next();
    }
}

app.use((req, res, next) => {
  res.locals.currentPath = req.path;
  next();
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




app.get('/', (req, res) => {
    res.render("index", {
        authenticated: isValidSession(req),
        name: req.session.name || ""
    });
});


app.get('/signup', (req, res) => {
  res.render("signup", { error: null, name: "", email: "" });
});

app.post('/submitUser', async (req, res) => {
    const { name, email, password } = req.body;

    const schema = Joi.object({
        name: Joi.string().max(20).required(),
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        return res.status(400).render("signup", {
            error: "Invalid input: " + validationResult.error.details[0].message,
            name,
            email
        });
    }

    const existingUser = await userCollection.findOne({ email });
    if (existingUser) {
        return res.status(409).render("signup", {
            error: "This email is already registered.",
            name,
            email
        });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, user_type: "user", password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.email = email;
    req.session.cookie.maxAge = expireTime;

    return res.render("members", {
    user: name,
    });
});


app.get('/login', (req, res) => {
    res.render("login", { error: null, email: "" });
});


app.post('/loggingin', async (req, res) => {
    const { email, password } = req.body;

    // Validate user input using Joi
    const schema = Joi.object({
        email: Joi.string().email().max(40).required(),
        password: Joi.string().max(20).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        return res.status(400).render("login", {
            error: "Invalid input. Please enter a valid email and password.",
            email: email || ""
        });
    }

    // Query database for user
    const result = await userCollection.find({ email }).project({
        name: 1,
        email: 1,
        password: 1,
        user_type: 1
    }).toArray();

    if (result.length !== 1) {
        return res.status(401).render("login", {
            error: "Email not found.",
            email
        });
    }

    // Compare password using bcrypt
    const passwordMatch = await bcrypt.compare(password, result[0].password);
    if (passwordMatch) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.email = result[0].email;
        req.session.user_type = result[0].user_type || "user";
        req.session.cookie.maxAge = expireTime;

        return res.render("members", {
            user: result[0].name,
        });
    } else {
        return res.status(401).render("login", {
            error: "Invalid email/password combination.",
            email
        });
    }
});


app.use('/members', sessionValidation, (req, res) => {
    res.render("members", {user: req.session.name});
});

app.get('/logout', (req,res) => {
    req.session.destroy();
    res.render("index", {
        authenticated: false,
        name: ""
    });
});

app.get('/admin', sessionValidation, adminAuthorization, async (req, res) => {
    const users = await userCollection.find().project({ name: 1, email: 1, user_type: 1 }).toArray();
    res.render("admin", { users });
});

app.get('/admin/promote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne({ email }, { $set: { user_type: "admin" } });
    res.redirect('/admin');
});

app.get('/admin/demote/:email', sessionValidation, adminAuthorization, async (req, res) => {
    const email = req.params.email;
    await userCollection.updateOne({ email }, { $set: { user_type: "user" } });
    res.redirect('/admin');
});



app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
    res.status(404);
    res.render("404");
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});