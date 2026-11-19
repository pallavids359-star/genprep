require("dotenv").config();
require("dns").setServers(["8.8.8.8", "1.1.1.1"]);
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const [email, password, name = "Admin"] = process.argv.slice(2);
if (!email || !password || password.length < 6) { console.log("Usage: node seed/createAdmin.js email password Name"); process.exit(1); }
mongoose.connect(process.env.MONGO_URI).then(async () => {
  const users = mongoose.connection.db.collection("users");
  const passwordHash = await bcrypt.hash(password, 10);
  const lower = email.trim().toLowerCase();
  const result = await users.updateOne(
    { email: lower },
    { $set: { passwordHash, role: "admin", status: "active" }, $unset: { password: "" },
      $setOnInsert: { email: lower, name, isEmailVerified: true, streak: { current: 0, longest: 0 }, createdAt: new Date() },
      $currentDate: { updatedAt: true } },
    { upsert: true }
  );
  await users.updateOne({ email: lower, $or: [{ name: { $exists: false } }, { name: "" }] }, { $set: { name } });
  console.log(result.upsertedCount ? "Created admin " + lower : "Updated " + lower + ": password reset, role=admin");
  process.exit(0);
}).catch((err) => { console.log("Error: " + err.message); process.exit(1); });
