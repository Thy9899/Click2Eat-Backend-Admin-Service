require("dotenv").config();
const express = require("express");
const morgan = require("morgan");
const connectDB = require("./src/util/db");
const adminRoutes = require("./src/routes/admin.route");
const cors = require("cors");

const app = express();
// app.use(
//   cors({
//     origin: "http://localhost:5173",
//     credentials: true,
//   })
// );
// app.options(/.*/, cors());
app.use(cors());

app.use(express.json());
app.use(morgan("dev"));

// connect MongoDB
connectDB();

// static images
app.use("/Images", express.static("public/Images"));

// routes
app.use("/api/admins", adminRoutes);

const PORT = process.env.PORT || 5001;
app.listen(PORT, () => console.log(`✅ Admin service running on port ${PORT}`));
