// Import required modules using CommonJS
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const MongoStore = require("connect-mongo");
const path = require("path");
const dotenv = require("dotenv");

// Load environment variables
dotenv.config();

// Database Connection
require("./config/db"); // Using the db.js connection

// Passport Config
require("./config/passport")(passport);

// Initialize Express App
const app = express();

// Middleware to parse JSON and URL-encoded data
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// EJS as View Engine
app.set("view engine", "ejs");
app.set("views", path.join(__dirname, "views"));

// Serve Static Files (CSS, JS, Images)
app.use(express.static(path.join(__dirname, "public")));

// Session Management
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({ mongoUrl: process.env.MONGO_URI }),
    cookie: { maxAge: 1000 * 60 * 60 * 24 }, // 1 day
  })
);

// Initialize Passport for Authentication
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use("/auth", require("./routes/authRoutes"));
app.use("/user", require("./routes/userRoutes"));
app.use("/url", require("./routes/urlRoutes"));

// Home Route
app.get("/", (req, res) => {
  if (req.isAuthenticated()) {
    return res.redirect("/user/dashboard");
  }
  res.render("login", { error: null, success: null });
});

// Error Handling Middleware
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(500).send("Something went wrong!");
});

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
