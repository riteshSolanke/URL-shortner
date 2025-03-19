const express = require("express");
const {
  createShortUrl,
  getUserUrls,
  redirectUrl,
} = require("../controllers/urlController");
const { ensureAuthenticated } = require("../middleware/authMiddleware");
const { validateUrl } = require("../middleware/validateUrl");

const router = express.Router();

router.post("/shorten", ensureAuthenticated, validateUrl, createShortUrl);
router.get("/dashboard", ensureAuthenticated, getUserUrls);
router.get("/:shortUrl", redirectUrl);

module.exports = router;
