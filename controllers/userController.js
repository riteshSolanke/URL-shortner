const Url = require("../models/Url");

exports.getDashboard = async (req, res) => {
  try {
    const urls = await Url.find({ user: req.user._id });
    res.render("dashboard", { user: req.user, urls, error: null });
  } catch (error) {
    console.error("Error fetching dashboard data:", error);
    res.render("dashboard", {
      error: "Failed to load data. Please try again.",
      urls: [],
    });
  }
};
