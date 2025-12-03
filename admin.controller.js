const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Admin = require("../models/admin.model");

const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1h";
const SALT_ROUNDS = 10;

// REGISTER
const register = async (req, res) => {
  try {
    const { email, username, password, role } = req.body;
    if (!email || !username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const existing = await Admin.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    const newAdmin = await Admin.create({
      email,
      username,
      password: hashedPassword,
      role: role || "user", // ⭐ Default role
    });

    return res.status(201).json({
      admin_id: newAdmin._id,
      email: newAdmin.email,
      username: newAdmin.username,
      role: newAdmin.role,
      createdAt: newAdmin.createdAt,
    });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// LOGIN
const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await Admin.findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    const token = jwt.sign(
      {
        admin_id: user._id,
        email: user.email,
        username: user.username,
        image: user.image,
        role: user.role,
        is_admin: user.is_admin,
      },
      JWT_SECRET,
      { expiresIn: JWT_EXPIRES }
    );

    return res.json({
      user: {
        admin_id: user._id,
        email: user.email,
        username: user.username,
        image: user.image,
        role: user.role,
        is_admin: user.is_admin,
      },
      token,
    });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// GET ALL ADMINS
const getAllAdmins = async (req, res) => {
  try {
    // Check role (only admin allowed)
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied: Admins only",
      });
    }

    const admins = await Admin.find();

    return res.json({ success: true, data: admins });
  } catch (err) {
    console.error("Get all admins error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// UPDATE ADMIN
const updateAdmin = async (req, res) => {
  try {
    const { id } = req.params;
    const { email, username, password } = req.body;

    const admin = await Admin.findById(id);
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    if (req.file) {
      admin.image = `/Images/${req.file.filename}`;
    }

    if (email) admin.email = email;
    if (username) admin.username = username;
    if (password && password.trim()) {
      admin.password = await bcrypt.hash(password, SALT_ROUNDS);
    }

    await admin.save();

    return res.json({
      message: "Admin updated successfully",
      admin: {
        admin_id: admin._id,
        email: admin.email,
        username: admin.username,
        image: admin.image,
      },
    });
  } catch (err) {
    console.error("Update error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

//DELETE ADMIN
const deleteAdmin = async (req, res) => {
  try {
    const { id } = req.params;

    const admin = await Admin.findByIdAndDelete(id);
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    return res.json({ message: "Admin deleted successfully" });
  } catch (err) {
    console.error("Delete error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

module.exports = { register, login, getAllAdmins, updateAdmin, deleteAdmin };
