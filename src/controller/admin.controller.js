const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Admin = require("../models/admin.model");
const cloudinary = require("../config/cloudinary");

// JWT secret and options
const JWT_SECRET = process.env.JWT_SECRET || "your-secret-key";
const JWT_EXPIRES = process.env.JWT_EXPIRES || "1h";
const SALT_ROUNDS = 10;

// =======================================
// Upload buffer to Cloudinary
// This function uploads the received image (file buffer)
// to Cloudinary inside the folder "customer_profiles"
// =======================================
const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    cloudinary.uploader
      .upload_stream({ folder: "customer_profiles" }, (err, result) => {
        if (err) reject(err);
        else resolve(result.secure_url);
      })
      .end(fileBuffer);
  });
};

// =======================================
// REGISTER ADMIN / USER
// =======================================
const register = async (req, res) => {
  try {
    const { email, username, password, role } = req.body;

    // Check if required fields exist
    if (!email || !username || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    // Check if email or username already exists
    const existing = await Admin.findOne({ $or: [{ email }, { username }] });
    if (existing) {
      return res.status(409).json({ message: "User already exists" });
    }

    // Hash password before saving to database
    const hashedPassword = await bcrypt.hash(password, SALT_ROUNDS);

    // Create new admin/user
    const newAdmin = await Admin.create({
      email,
      username,
      password: hashedPassword,
      role: role || "user", // default role is "user"
    });

    // Return response (no password included)
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

// =======================================
// LOGIN
// =======================================
const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Find user by email
    const user = await Admin.findOne({ email });
    if (!user)
      return res.status(401).json({ message: "Invalid email or password" });

    // Compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch)
      return res.status(401).json({ message: "Invalid email or password" });

    // Create JWT token
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

    // Send user info + token
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

// =======================================
// GET ALL ADMINS (Only Admin Role Can Access)
// =======================================
const getAllAdmins = async (req, res) => {
  try {
    // Check permission
    if (req.user.role !== "admin") {
      return res.status(403).json({
        success: false,
        message: "Access denied: Admins only",
      });
    }

    // Fetch all admins
    const admins = await Admin.find();
    return res.json({ success: true, data: admins });
  } catch (err) {
    console.error("Get all admins error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// =======================================
// UPDATE ADMIN (with optional profile image upload)
// =======================================
const updateAdmin = async (req, res) => {
  try {
    const { id } = req.params;
    const { email, username, password } = req.body;

    // Find admin by ID
    const admin = await Admin.findById(id);
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    // If new image uploaded → upload to Cloudinary
    if (req.file) {
      const cloudinaryUrl = await uploadToCloudinary(req.file.buffer);
      admin.image = cloudinaryUrl;
    }

    // Update fields
    if (email) admin.email = email;
    if (username) admin.username = username;

    // Update password only if provided
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

// =======================================
// CHANGE PASSWORD
// =======================================
const changePassword = async (req, res) => {
  try {
    const { id } = req.params;
    const { currentPassword, newPassword } = req.body;

    const admin = await Admin.findById(id);
    if (!admin) return res.status(404).json({ message: "Admin not found" });

    // Check if current password correct
    const isMatch = await bcrypt.compare(currentPassword, admin.password);
    if (!isMatch)
      return res.status(400).json({ message: "Current password is incorrect" });

    // Hash new password
    admin.password = await bcrypt.hash(newPassword, SALT_ROUNDS);
    await admin.save();

    return res.json({ message: "Password updated successfully" });
  } catch (err) {
    console.error("Change password error:", err);
    return res.status(500).json({ message: "Internal server error" });
  }
};

// =======================================
// DELETE ADMIN
// =======================================
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

module.exports = {
  register,
  login,
  getAllAdmins,
  changePassword,
  updateAdmin,
  deleteAdmin,
};
