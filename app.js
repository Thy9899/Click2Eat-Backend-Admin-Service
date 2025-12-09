require("dotenv").config(); // Load environment variables from .env file

const express = require("express");
const morgan = require("morgan");
const connectDB = require("./src/util/db");
const adminRoutes = require("./src/routes/admin.route");
const cors = require("cors");

const app = express();

/* ============================================================
   CORS CONFIGURATION
   ============================================================ */

// Simple CORS (allows all origins)
app.use(cors());

// If you want to allow only your frontend, uncomment this:
// app.use(
//   cors({
//     origin: "http://localhost:5173", // React/Vite frontend URL
//     credentials: true,               // Allow cookies/auth headers
//   })
// );

// Enable preflight for all routes
// app.options(/.*/, cors());

/* ============================================================
   MIDDLEWARE
   ============================================================ */

// Parse incoming JSON from requests
app.use(express.json());

// Logger — prints request info (method, route, time)
app.use(morgan("dev"));

/* ============================================================
   CONNECT TO MONGODB
   ============================================================ */
connectDB();

/* ============================================================
   STATIC IMAGE FOLDER
   ============================================================ */
// Any image inside /public/Images can be accessed like:
// http://localhost:5001/Images/example.png
app.use("/Images", express.static("public/Images"));

/* ============================================================
   ROUTES
   ============================================================ */

// All admin-related API routes start with /api/admins
app.use("/api/admins", adminRoutes);

/* ============================================================
   START SERVER
   ============================================================ */

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`✅ Admin service running on port ${PORT}`));
