const router = require("express").Router();
const passport = require("passport");
require("dotenv").config();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const mysql = require("mysql2/promise"); // Import the promise-compatible version

// Define an async function to handle the initialization
const initializeConnection = async () => {
  try {
    // Create the connection to database
    const connection = await mysql.createConnection({
      host: process.env.DB_HOST,
      user: process.env.DB_USER,
      password: process.env.DB_PASS,
      database: process.env.DB_NAME,
    });
    return connection; // Return the connection
  } catch (error) {
    console.error("Error initializing database connection:", error);
    throw error;
  }
};

// Initialize the connection outside of the route handler
let connection; // Declare a variable to store the connection

initializeConnection()
  .then((conn) => {
    connection = conn;
    console.log("Database connection initialized successfully");
  })
  .catch((error) => {
    console.error("Failed to initialize database connection:", error);
  });

  router.get("/login/success", async (req, res) => {
	try {
	  if (req.isAuthenticated()) {
		const email = req.user.emails[0].value;
		const selectQuery = `SELECT * FROM users WHERE email = ?`;
		const [rows] = await connection.query(selectQuery, [email]);
  
		if (rows.length > 0) {
		  // หากมีผู้ใช้งานอยู่แล้วในฐานข้อมูล
		  var token = jwt.sign(
			{
			  user_id: rows[0].user_id,
			  email: rows[0].email,
			  role: rows[0].role,
			},
			process.env.JWT_SECRET, // ใช้ค่า secret จาก environment variable
			{
			  expiresIn: "1h",
			}
		  );
  
		  res.status(200).json({
			status: "ok",
			error: false,
			message: "Successfully Logged In",
			user: req.user,
			token,
		  });
		} else {
		  // หากไม่พบผู้ใช้งาน ให้ทำการเพิ่มผู้ใช้งานใหม่ลงในฐานข้อมูล
		  const picture = req.user.photos[0].value;
		  const insertUserQuery =
			"INSERT INTO users (email, password, role, picture) VALUES (?, '', 'customer', ?)";
		  const [insertUserResult] = await connection.query(insertUserQuery, [email,picture]);
  
		  if (insertUserResult.affectedRows > 0) {
			const cust_name = req.user.name.givenName;
			const cust_surname = req.user.name.familyName;
			const insertCustomerQuery =
			  "INSERT INTO customers (user_id, cust_name, cust_surname, sex, address, tel) VALUES (?, ?, ?, 'ไม่ระบุ', 'ไม่ระบุ', 'ไม่ระบุ')";
			const [insertCustomerResult] = await connection.query(insertCustomerQuery, [
			  insertUserResult.insertId,
			  cust_name,
			  cust_surname
			]);
  
			if (insertCustomerResult.affectedRows > 0) {
			  var token = jwt.sign(
				{
				  user_id: insertUserResult.insertId,
				  email: email,
				  role: "customer",
				},
				process.env.JWT_SECRET, // ใช้ค่า secret จาก environment variable
				{
				  expiresIn: "1h",
				}
			  );
  
			  res.status(200).json({
				status: "ok",
				error: false,
				message: "Successfully Logged In",
				user: req.user,
				token,
			  });
			} else {
			  throw new Error("Failed to insert customer data");
			}
		  } else {
			throw new Error("Failed to insert user data");
		  }
		}
	  } else {
		res.status(403).json({ error: true, message: "Not Authorized" });
	  }
	} catch (error) {
	  console.error("Error processing login:", error);
	  res.status(500).json({ error: true, message: "Internal Server Error" });
	}
  });  

router.get("/login/failed", (req, res) => {
  res.status(401).json({
    error: true,
    message: "Log in failure",
  });
});

router.get("/google", passport.authenticate("google", ["profile", "email"]));

router.get(
  "/google/callback",
  passport.authenticate("google", {
    successRedirect: `${process.env.CLIENT_URL}homepage`,
    failureRedirect: "/login/failed",
  })
);

// Route สำหรับการ logout
router.get("/logout", (req, res) => {
	if (req.isAuthenticated()) {
	  req.logout(() => {}); // ใส่ฟังก์ชัน callback ที่ไม่ทำอะไรเลย
	  res.redirect(process.env.CLIENT_URL);
	} else {
	  
	}
  });

module.exports = router;
