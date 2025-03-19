const mongoose = require("mongoose");
const shortid = require("shortid");

const urlSchema = new mongoose.Schema({
  originalUrl: String,
  shortUrl: { type: String, unique: true, default: shortid.generate },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  createdAt: { type: Date, default: Date.now },
  clickCount: { type: Number, default: 0 },
  qrCode: String,
});

const Url = mongoose.model("Url", urlSchema);
module.exports = Url;
