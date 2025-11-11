
const cors = require("cors");

const bcrypt = require("bcrypt");
const express = require("express");
const { UserModal } = require("./db");
const jwt = require("jsonwebtoken");
const mongoose = require("mongoose");
const { z } = require("zod");

const privatekey = process.env.JWT_SECRET;

mongoose.connect(process.env.MONGO_URL);

const app = express();
app.use(express.json());
app.use(cors());

app.post("/signup", async function (req, res) {
  const schema = z.object({
    email: z.string().email(),
    password: z
      .string()
      .min(8)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*[^a-zA-Z0-9])/,
        "Password must include upper, lower, and special character"
      ),
    name: z.string().min(3).max(30),
  });

  const parsed = schema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({
      message: "Invalid input",
      error: parsed.error.errors,
    });
  }

  const { email, password, name } = req.body;

  try {
    const existingUser = await UserModal.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await UserModal.create({ email, password: hashedPassword, name });

    res.status(201).json({ message: "Signup successful" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

app.post("/signin", async function (req, res) {
  const { email, password } = req.body;

  try {
    const user = await UserModal.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: user._id }, privatekey, { expiresIn: "1h" });
    res.json({
      message: "Login successful",
      token,
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

app.listen(3000, () => console.log("Server running on port 3000"));
