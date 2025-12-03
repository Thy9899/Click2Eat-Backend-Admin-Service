const express = require("express");
const router = express.Router();
const adminController = require("../controller/admin.controller");
const authenticateToken = require("../middleware/authMiddleware");
const authorizeRoles = require("../middleware/authorizeRoles");
const multer = require("multer");
const path = require("path");
const fs = require("fs");

// Ensure upload folder exists
const uploadDir = "./public/Images";
if (!fs.existsSync(uploadDir)) fs.mkdirSync(uploadDir, { recursive: true });

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, uploadDir),
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname);
    cb(null, Date.now() + "-" + file.fieldname + ext);
  },
});

const upload = multer({ storage });

// AUTH
router.post("/register", adminController.register);
router.post("/login", adminController.login);

// Only admin can access all admins
router.get(
  "/profile",
  authenticateToken,
  authorizeRoles("admin"),
  adminController.getAllAdmins
);

// Both admin & user can update their own profile
router.put(
  "/profile/:id",
  authenticateToken,
  // authorizeRoles("admin", "cashier", "user"),
  upload.single("image"),
  adminController.updateAdmin
);

// Only admin can delete
router.delete(
  "/profile/:id",
  authenticateToken,
  authorizeRoles("admin"),
  adminController.deleteAdmin
);

module.exports = router;
