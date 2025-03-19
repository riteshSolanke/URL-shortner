const Url = require("../models/Url");
const qrcode = require("qrcode");

// Generate QR Code
const generateQRCode = async (shortUrl) => {
  const baseUrl =
    process.env.NODE_ENV === "production"
      ? process.env.PRODUCTION_URL
      : "http://localhost:3000";

  const qrCodeData = await qrcode.toDataURL(`${baseUrl}/${shortUrl}`);
  return qrCodeData;
};

// Create Short URL
exports.createShortUrl = async (req, res) => {
  const { originalUrl } = req.body;
  try {
    const newUrl = new Url({ originalUrl, userId: req.user._id });

    newUrl.qrCode = await generateQRCode(newUrl.shortUrl);
    await newUrl.save();
    res.redirect("/url/dashboard");
  } catch (error) {
    res.render("dashboard", { error: "Error creating URL. Try again." });
  }
};

// Track Clicks
exports.redirectUrl = async (req, res) => {
  try {
    const url = await Url.findOne({ shortUrl: req.params.shortUrl });
    if (!url) return res.status(404).send("URL not found");

    url.clickCount += 1;
    await url.save();
    res.redirect(url.originalUrl);
  } catch (error) {
    res.status(500).send("Server Error");
  }
};

// Display User Dashboard
exports.getUserUrls = async (req, res) => {
  try {
    const urls = await Url.find({ userId: req.user._id }).sort({
      createdAt: -1,
    });
    res.render("dashboard", { urls, user: req.user, error: null });
  } catch (error) {
    res.render("dashboard", { error: "Error fetching URLs." });
  }
};
