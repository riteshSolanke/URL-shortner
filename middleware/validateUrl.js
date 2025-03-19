const validUrl = require("valid-url");

exports.validateUrl = (req, res, next) => {
  const { originalUrl } = req.body;
  if (!validUrl.isUri(originalUrl)) {
    return res.render("dashboard", {
      error: "Invalid URL. Please enter a valid URL.",
    });
  }
  next();
};
