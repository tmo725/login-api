require("dotenv").config();
const express = require("express");
const cors = require("cors");
const passport = require("passport");
const authRoute = require("./routes/auth");
const cookieSession = require("express-session");
const passportSetup = require("./passport");
const app = express();

var bodyParser = require("body-parser");
var jsonParser = bodyParser.json();
const bcrypt = require("bcrypt");
const sanitizeHtml = require("sanitize-html");
const saltRounds = 10;
var jwt = require("jsonwebtoken");
const secret = process.env.JWT_SECRET;

app.use(cors());
const mysql = require("mysql2");

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASS,
  database: process.env.DB_NAME,
});

app.post("/register", jsonParser, function (req, res, next) {
  // Check for empty values and trim whitespace
  const { email, password, cust_name, cust_surname, sex, address, tel } =
    req.body;
  if (
    !email ||
    !password ||
    !cust_name ||
    !cust_surname ||
    !sex ||
    !address ||
    !tel
  ) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Trim
  const trimmedEmail = email.trim();
  const trimmedPassword = password.trim();
  const trimmedCustName = cust_name.trim();
  const trimmedCustSurname = cust_surname.trim();
  const trimmedSex = sex.trim();
  const trimmedAddress = address.trim();
  const trimmedTel = tel.trim();

  // Sanitize user input
  const sanitizedEmail = sanitizeHtml(trimmedEmail);
  const sanitizedPassword = sanitizeHtml(trimmedPassword);
  const sanitizedCustName = sanitizeHtml(trimmedCustName);
  const sanitizedCustSurname = sanitizeHtml(trimmedCustSurname);
  const sanitizedSex = sanitizeHtml(trimmedSex);
  const sanitizedAddress = sanitizeHtml(trimmedAddress);
  const sanitizedTel = sanitizeHtml(trimmedTel);

  // Check email format using regex
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(trimmedEmail)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  // Check password format
  const passwordRegex =
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!%*#?&]{8,}$/;
  if (!passwordRegex.test(trimmedPassword)) {
    return res.status(400).json({
      error:
        "The password must be at least 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character.",
    });
  }

  // Check all fields are strings
  if (
    typeof trimmedEmail !== "string" ||
    typeof trimmedPassword !== "string" ||
    typeof trimmedCustName !== "string" ||
    typeof trimmedCustSurname !== "string" ||
    typeof trimmedSex !== "string" ||
    typeof trimmedAddress !== "string" ||
    typeof trimmedTel !== "string"
  ) {
    return res.status(400).json({ error: "Invalid format" });
  }

  // Proceed with hashing password and database operations
  bcrypt.hash(trimmedPassword, saltRounds, function (err, hash) {
    if (err) {
      console.log(err);
      return res.status(500).json({ error: "Password hashing error" });
    }
    try {
      connection.execute(
        "INSERT INTO users (email, password, role) VALUES (?, ?, 'customer')",
        [trimmedEmail, hash],
        function (err) {
          if (err) {
            console.log(err);
            return res.status(500).json({ error: "Database error" });
          }
          // Inserted user, now insert customer details
          connection.execute(
            "INSERT INTO customers (user_id, cust_name, cust_surname, sex, address, tel) VALUES ((SELECT LAST_INSERT_ID()), ?, ?, ?, ?, ?)",
            [
              trimmedCustName,
              trimmedCustSurname,
              trimmedSex,
              trimmedAddress,
              trimmedTel,
            ],
            function (err) {
              if (err) {
                console.log(err);
                return res.status(500).json({ error: "Database error" });
              }
              res.json({ status: "ok" });
            }
          );
        }
      );
    } catch (err) {
      console.log(err);
      res.status(500).json({ error: "Internal server error" });
    }
  });
});

app.post("/login", jsonParser, function (req, res, next) {
  const { email, password } = req.body; // ดึง email และ password จาก req.body

  // Check if email and password are provided and in string format
  if (
    !email ||
    !password ||
    typeof email !== "string" ||
    typeof password !== "string"
  ) {
    return res.status(400).json({ error: "Invalid format" });
  }

  // Validate email format
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).json({ error: "Invalid email format" });
  }

  try {
    // console.log(req.body.email, req.body.password); // เพิ่มบรรทัดนี้
    connection.execute(
      "SELECT * FROM users WHERE email = ?",
      [email], // ใช้ email ที่ดึงมาจาก req.body
      function (err, users, fields) {
        if (err) {
          console.log(err);
          return res.status(500).json({ error: "Database error" });
        }

        if (users.length == 0) {
          console.log(users);
          return res.json({ error: "no user found" });
        }

        bcrypt.compare(
          password, // ใช้ password ที่ดึงมาจาก req.body
          users[0].password,
          function (err, isLogin) {
            if (isLogin) {
              var token = jwt.sign(
                {
                  user_id: users[0].user_id, // เพิ่ม user_id จากข้อมูลของผู้ใช้
                  email: users[0].email, // เพิ่ม email จากข้อมูลของผู้ใช้
                  role: users[0].role, // เพิ่ม role จากข้อมูลของผู้ใช้
                },
                secret,
                {
                  expiresIn: "1h",
                }
              );

              res
                .status(200)
                .json({ status: "ok", message: "Login success", token });
            } else {
              res.json({ error: "Login failed" });
            }
          }
        );
      }
    );
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    if (token == null) return res.sendStatus(401); // Unauthorized
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
    console.log(decoded);
  } catch (err) {
    res.json({ message: "Unauthorized", error: err.message });
  }
});

app.get("/products", (req, res) => {
  const sql =
    "SELECT product_img_name AS imageURL, product_name, price_per_unit, product_type, product_id FROM products"; // เพิ่ม AS imageURL เพื่อเปลี่ยนชื่อฟิลด์
  connection.execute(sql, (err, result) => {
    // เปลี่ยน mysql เป็น connection ที่เราสร้างไว้
    if (err) {
      res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
      throw err;
    }
    res.json({ menuItems: result });
  });
});

app.get("/products/:productId", (req, res) => {
  const productId = req.params.productId;
  const sql =
    "SELECT product_img_name AS imageURL, product_name, price_per_unit, product_type, product_id, product_desc FROM products WHERE product_id = ?"; // เพิ่ม AS imageURL เพื่อเปลี่ยนชื่อฟิลด์
  connection.execute(sql, [productId], (err, result) => {
    // เปลี่ยน mysql เป็น connection ที่เราสร้างไว้
    if (err) {
      res.status(500).json({ error: "เกิดข้อผิดพลาดในการดึงข้อมูล" });
      throw err;
    }
    if (result.length === 0) {
      res.status(404).json({ error: "ไม่พบสินค้า" });
    } else {
      res.json(result[0]);
    }
  });
});

app.post("/add-to-cart", jsonParser, function (req, res, next) {
  try {
    const { user_id, product_id, quantity } = req.body; // รับข้อมูลผู้ใช้และสินค้าที่ต้องการเพิ่มลงในตะกร้า

    // คำสั่ง SQL เพื่อเพิ่มข้อมูลลงในตาราง carts
    const insertSql =
      "INSERT INTO carts (cart_user_id, cart_product_id, cart_quantity) VALUES (?, ?, ?)";
    // execute will internally call prepare and query
    connection.execute(
      insertSql,
      [user_id, product_id, quantity],
      function (err, result) {
        if (err) {
          console.log(err);
          return res.status(500).json({ error: "Database error" });
        }
        res.json({
          status: "ok",
          message: "Product added to cart successfully",
        });
      }
    );
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// รับคำขอ GET เพื่อดึงข้อมูลสินค้าในตะกร้าของผู้ใช้
app.get("/carts/:user_id", async (req, res) => {
  try {
    const { user_id } = req.params;
    const sql = `
      SELECT products.*, carts.cart_quantity, carts.cart_total_price
      FROM carts
      INNER JOIN products ON carts.cart_product_id = products.product_id
      WHERE carts.cart_user_id = ?
    `;
    const carts = await db.query(sql, [user_id]);
    res.json({ status: "ok", carts });
  } catch (error) {
    console.error("เกิดข้อผิดพลาดในการดึงข้อมูล:", error);
    res.status(500).json({ error: "Database error" });
  }
});

app.post("/user", jsonParser, function (req, res, next) {
  const { user_id } = req.body; // ดึง user_id จาก req.body

  try {
    connection.execute(
      `SELECT users.*, customers.cust_name
       FROM users
       LEFT JOIN customers ON users.user_id = customers.user_id
       WHERE users.user_id = ?`,
      [user_id],
      function (err, users, fields) {
        if (err) {
          console.log(err);
          return res.status(500).json({ error: "Database error" });
        }

        if (users.length === 0) {
          console.log(users);
          return res.json({ error: "No user found" });
        }

        // ส่งข้อมูลผู้ใช้กลับไปที่ frontend
        const user = {
          id: users[0].user_id,
          email: users[0].email,
          picture: users[0].email,
          cust_name: users[0].cust_name
          // เพิ่ม properties อื่นๆ ตามต้องการ
        };
        return res.json({ user });
      }
    );
  } catch (err) {
    console.log(err);
    res.status(500).json({ error: "Internal server error" });
  }
});


app.use(
  cookieSession({
    secret: "your_secret_key", // คีย์ลับสำหรับการเข้ารหัสข้อมูล session
    resave: false, // กำหนดว่า session จะถูกบันทึกลงฐานข้อมูลทุกครั้งที่มีการแก้ไขหรือไม่
    saveUninitialized: true, // กำหนดว่า session จะถูกสร้างขึ้นใหม่ทุกครั้งที่มีการร้องขอจาก client หรือไม่
    cookie: {
      secure: false, // กำหนดว่า cookie จะถูกส่งกับการร้องขอที่เป็น HTTPS เท่านั้นหรือไม่
      maxAge: 3600000, // 1 ชั่วโมง
    },
  })
);

app.use(passport.initialize());
app.use(passport.session());

app.use(
  cors({
    origin: "http://localhost:3000",
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);

app.use("/auth", authRoute);

const port = process.env.PORT || 8080;
app.listen(port, jsonParser, () =>
  console.log(`Listenting on port ${port}...`)
);
