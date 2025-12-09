const express = require("express");
const router = express.Router();
const adminController = require("../controller/admin.controller");
const authenticateToken = require("../middleware/authMiddleware");
const authorizeRoles = require("../middleware/authorizeRoles");
const multer = require("multer");

// =======================================
// Multer memory storage
// - File is stored in memory as a buffer
// - No physical file saved on disk
// - Useful for Cloudinary uploads
// =======================================
const upload = multer({ storage: multer.memoryStorage() });

/* ============================================================
   AUTH ROUTES
   ============================================================ */

// REGISTER (anyone can register)
router.post("/register", adminController.register);

// LOGIN (returns JWT token)
router.post("/login", adminController.login);

/* ============================================================
   ADMIN ROUTES
   ============================================================ */

// =======================================
// GET ALL ADMINS
// - Must be logged in (authenticateToken)
// - Must have role "admin"
// =======================================
router.get(
  "/profile",
  authenticateToken, // Check if token valid
  authorizeRoles("admin"), // Only admins allowed
  adminController.getAllAdmins
);

/* ============================================================
   UPDATE PROFILE
   ============================================================ */

// =======================================
// UPDATE ADMIN PROFILE BY ID
// - Must be logged in
// - Upload image with multer (file stored in memory)
// =======================================
router.put(
  "/profile/:id",
  authenticateToken,
  // authorizeRoles("admin", "cashier", "user"), // Optional role protection
  upload.single("image"), // Accept image field
  adminController.updateAdmin
);

// =======================================
// CHANGE PASSWORD
// ❌ BUG: This was calling updateAdmin (wrong!)
// I kept your code but commented the issue.
// If you want, I can create a correct changePassword route.
// =======================================
router.put(
  "/change-password/:id",
  authenticateToken,
  upload.single("image"), // Not needed for password change but kept as you wrote
  adminController.updateAdmin // ⚠️ This should be: adminController.changePassword
);

/* ============================================================
   DELETE ADMIN
   ============================================================ */

// =======================================
// DELETE ADMIN BY ID
// - Must be logged in
// - Only admin role allowed
// =======================================
router.delete(
  "/profile/:id",
  authenticateToken,
  authorizeRoles("admin"),
  adminController.deleteAdmin
);

module.exports = router;
