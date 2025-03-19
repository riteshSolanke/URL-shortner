const express = require("express");
const {
  registerUser,
  loginUser,
  logoutUser,
  forgotPassword,
  resetPassword,
  verifyOtp,
} = require("../controllers/authController");
const router = express.Router();

router.get("/register", (req, res) =>
  res.render("register", { error: null, success: null })
);
router.post("/register", registerUser);

router.get("/login", (req, res) =>
  res.render("login", { error: null, success: null })
);
router.post("/login", loginUser);

router.get("/logout", logoutUser);

router.get("/forgot-password", (req, res) =>
  res.render("forgot-password", { error: null, success: null })
);
router.post("/forgot-password", forgotPassword);

router.get("/verify-otp", (req, res) =>
  res.render("verify-otp", { error: null, success: null })
);
router.post("/verify-otp", verifyOtp);

router.get("/reset-password", (req, res) =>
  res.render("reset-password", { error: null, success: null })
);
router.post("/reset-password", resetPassword);

module.exports = router;
