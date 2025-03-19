const express = require("express");
const router = express.Router();
const { ensureAuthenticated } = require("../middleware/authMiddleware");
const userController = require("../controllers/userController");

// Dashboard Route (Protected)
router.get("/dashboard", ensureAuthenticated, userController.getDashboard);

module.exports = router;
