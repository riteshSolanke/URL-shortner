const bcrypt = require("bcryptjs");
const User = require("../models/User");
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const passport = require("passport");

// Configure Nodemailer
const transporter = nodemailer.createTransport({
  host: "smtp.ethereal.email",
  port: 587,
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_PASS,
  },
});

// -------------------- Register User --------------------
exports.getSignupPage = (req, res) => {
  res.render("register", { error: null, success: null });
};

exports.registerUser = async (req, res) => {
  const { name, email, password } = req.body;
  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.render("login", {
        error: "Email is already registered.",
        success: null,
      });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ name, email, password: hashedPassword });
    await newUser.save();

    res.render("login", {
      success: "Registration successful! Please login.",
      error: null,
    });
  } catch (error) {
    console.error("Signup Error:", error);
    res.render("signup", {
      error: "Error during signup. Please try again.",
      success: null,
    });
  }
};

// -------------------- Login User --------------------
exports.getLoginPage = (req, res) => {
  res.render("login", { error: null, success: null });
};

exports.loginUser = (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      return res.render("login", {
        error: "Login failed. Please try again.",
        success: null,
      });
    }
    if (!user) {
      return res.render("login", { error: info.message, success: null });
    }
    req.logIn(user, (err) => {
      if (err) {
        return res.render("login", {
          error: "Failed to log in. Please try again.",
          success: null,
        });
      }
      res.redirect("/url/dashboard");
    });
  })(req, res, next);
};

// -------------------- Logout User --------------------
exports.logoutUser = (req, res) => {
  req.logout((err) => {
    if (err) {
      console.error("Logout Error:", err);
      return res.status(500).send("Logout failed. Please try again.");
    }
    req.session.destroy(() => {
      res.redirect("/auth/login");
    });
  });
};

// -------------------- Send OTP for Password Reset --------------------
exports.getForgotPasswordPage = (req, res) => {
  res.render("forgot-password", { error: null, success: null });
};

exports.forgotPassword = async (req, res) => {
  const { email } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.render("forgot-password", {
        error: "User not found.",
        success: null,
      });
    }

    const otp = crypto.randomInt(100000, 999999).toString();
    user.otp = otp;
    user.otpExpiry = new Date(Date.now() + 3 * 60 * 1000); // OTP valid for 3 minutes
    await user.save();

    await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to: user.email,
      sub: `Your OTP for password reset`,
      text: `Your OTP is ${otp}. It is valid for only three minutes`,
      html: "<p><b>Hello</b> to myself!</p>",
    });

    res.render("verify-otp", {
      success: "OTP sent to your email.",
      error: null,
    });
  } catch (error) {
    console.error("Forgot Password Error:", error);
    res.render("forgot-password", {
      error: "Failed to send OTP. Please try again.",
      success: null,
    });
  }
};

// -------------------- Verify OTP --------------------
exports.getVerifyOtpPage = (req, res) => {
  res.render("verify-otp", { error: null, success: null });
};

exports.verifyOtp = async (req, res) => {
  const { email, otp } = req.body;

  try {
    const user = await User.findOne({ email });

    if (!user || user.otp !== otp || user.otpExpiry < new Date()) {
      return res.render("verify-otp", {
        error: "Invalid or expired OTP.",
        success: null,
      });
    }

    user.otp = null;
    user.otpExpiry = null;
    await user.save();

    req.session.resetEmail = email;
    res.render("reset-password", {
      success: "OTP Verified! Please reset your password.",
      error: null,
    });
  } catch (error) {
    console.error("OTP Verification Error:", error);
    res.render("verify-otp", {
      error: "Failed to verify OTP. Please try again.",
      success: null,
    });
  }
};

// -------------------- Reset Password --------------------
exports.getResetPasswordPage = (req, res) => {
  res.render("reset-password", { error: null, success: null });
};

exports.resetPassword = async (req, res) => {
  const { password } = req.body;
  const email = req.session.resetEmail;

  if (!email) {
    return res.redirect("/auth/login");
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.redirect("/auth/login");
    }

    user.password = await bcrypt.hash(password, 10);
    await user.save();

    req.session.resetEmail = null;
    res.render("login", {
      success: "Password reset successful! Please log in.",
      error: null,
    });
  } catch (error) {
    console.error("Reset Password Error:", error);
    res.render("reset-password", {
      error: "Failed to reset password. Please try again.",
      success: null,
    });
  }
};
