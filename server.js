require("dotenv").config();
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");
const rateLimit = require("express-rate-limit");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
if (!process.env.DATABASE_URL || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Missing DATABASE_URL or JWT_SECRET (must be at least 32 characters).");
  process.exit(1);
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : undefined
});
app.set("trust proxy", 1);
app.use(express.json({ limit: "30kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

async function initDb() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      phone VARCHAR(20) UNIQUE NOT NULL,
      name VARCHAR(100) NOT NULL DEFAULT 'Customer',
      password_hash TEXT NOT NULL,
      role VARCHAR(10) NOT NULL DEFAULT 'client' CHECK (role IN ('admin','client')),
      package_name VARCHAR(80) NOT NULL DEFAULT '30 Mbps',
      monthly_bill INTEGER NOT NULL DEFAULT 500,
      status VARCHAR(20) NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS payments (
      id SERIAL PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      method VARCHAR(20) NOT NULL,
      sender_phone VARCHAR(20) NOT NULL,
      transaction_id VARCHAR(100) NOT NULL,
      amount INTEGER NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      reviewed_at TIMESTAMPTZ,
      reviewed_by INTEGER REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS connection_requests (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      name VARCHAR(100) NOT NULL,
      phone VARCHAR(20) NOT NULL,
      address TEXT NOT NULL,
      package_name VARCHAR(80) NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','contacted','completed','rejected')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS complaints (
      id SERIAL PRIMARY KEY,
      user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
      phone VARCHAR(20) NOT NULL,
      category VARCHAR(80) NOT NULL,
      details TEXT NOT NULL,
      status VARCHAR(20) NOT NULL DEFAULT 'open' CHECK (status IN ('open','in_progress','resolved')),
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);

  const adminPhone = (process.env.ADMIN_PHONE || "").trim();
  const adminPassword = process.env.ADMIN_PASSWORD || "";
  if (adminPhone && adminPassword) {
    const exists = await pool.query("SELECT id FROM users WHERE phone=$1", [adminPhone]);
    if (exists.rowCount === 0) {
      const hash = await bcrypt.hash(adminPassword, 12);
      await pool.query(
        "INSERT INTO users(phone,name,password_hash,role,package_name,monthly_bill) VALUES($1,$2,$3,'admin','Admin',0)",
        [adminPhone, "Dhamrai Net Admin", hash]
      );
      console.log("Initial admin account created from environment variables.");
    }
  }
}

function auth(req, res, next) {
  const token = req.cookies.dn_session;
  if (!token) return res.status(401).json({ error: "অনুগ্রহ করে লগইন করুন।" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.clearCookie("dn_session");
    return res.status(401).json({ error: "সেশন শেষ হয়েছে। আবার লগইন করুন।" });
  }
}
function adminOnly(req, res, next) {
  if (req.user?.role !== "admin") return res.status(403).json({ error: "এই কাজটি শুধু অ্যাডমিন করতে পারবেন।" });
  next();
}
function cleanPhone(value) {
  return String(value || "").replace(/[^\d+]/g, "").slice(0, 20);
}
function requiredString(value, max = 1000) {
  return typeof value === "string" ? value.trim().slice(0, max) : "";
}
const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false,
  message: { error: "অনেকবার চেষ্টা হয়েছে। ১৫ মিনিট পর আবার চেষ্টা করুন।" } });

app.get("/api/config", (req, res) => res.json({
  brand: "Dhamrai Net",
  paymentNumber: process.env.PAYMENT_NUMBER || "",
  paymentMethods: ["bKash", "Nagad", "Rocket"]
}));

app.post("/api/login", loginLimiter, async (req, res) => {
  try {
    const phone = cleanPhone(req.body.phone);
    const password = requiredString(req.body.password, 200);
    const result = await pool.query("SELECT * FROM users WHERE phone=$1", [phone]);
    const user = result.rows[0];
    if (!user || user.status !== "active" || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: "ফোন নম্বর বা পাসওয়ার্ড সঠিক নয়।" });
    }
    const token = jwt.sign({ id: user.id, phone: user.phone, role: user.role }, JWT_SECRET, { expiresIn: "8h" });
    res.cookie("dn_session", token, {
      httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax",
      maxAge: 8 * 60 * 60 * 1000, path: "/"
    });
    res.json({ user: { id: user.id, phone: user.phone, name: user.name, role: user.role,
      packageName: user.package_name, monthlyBill: user.monthly_bill } });
  } catch (e) {
    console.error(e); res.status(500).json({ error: "লগইন করা যায়নি। সার্ভার সেটিংস পরীক্ষা করুন।" });
  }
});
app.post("/api/logout", (req, res) => { res.clearCookie("dn_session", { path: "/" }); res.json({ ok: true }); });
app.get("/api/me", auth, async (req, res) => {
  const r = await pool.query("SELECT id,phone,name,role,package_name,monthly_bill,status FROM users WHERE id=$1", [req.user.id]);
  if (!r.rowCount) return res.status(401).json({ error: "অ্যাকাউন্ট পাওয়া যায়নি।" });
  const u = r.rows[0];
  res.json({ user: { id:u.id, phone:u.phone, name:u.name, role:u.role, packageName:u.package_name,
    monthlyBill:u.monthly_bill, status:u.status } });
});

app.get("/api/client/summary", auth, async (req, res) => {
  if (req.user.role !== "client") return res.status(403).json({ error: "গ্রাহক অ্যাকাউন্ট প্রয়োজন।" });
  const [userR, paymentR] = await Promise.all([
    pool.query("SELECT id,phone,name,package_name,monthly_bill,status FROM users WHERE id=$1", [req.user.id]),
    pool.query("SELECT id,method,sender_phone,transaction_id,amount,status,created_at FROM payments WHERE user_id=$1 ORDER BY id DESC LIMIT 10", [req.user.id])
  ]);
  res.json({ user: userR.rows[0], payments: paymentR.rows });
});
app.post("/api/client/payments", auth, async (req, res) => {
  if (req.user.role !== "client") return res.status(403).json({ error: "গ্রাহক অ্যাকাউন্ট প্রয়োজন।" });
  const method = requiredString(req.body.method, 20);
  const sender = cleanPhone(req.body.senderPhone);
  const transactionId = requiredString(req.body.transactionId, 100);
  const amount = Number(req.body.amount);
  if (!["bKash","Nagad","Rocket"].includes(method) || sender.length < 10 || transactionId.length < 4 || !Number.isInteger(amount) || amount < 1 || amount > 1000000)
    return res.status(400).json({ error: "সব পেমেন্ট তথ্য সঠিকভাবে দিন।" });
  const r = await pool.query("INSERT INTO payments(user_id,method,sender_phone,transaction_id,amount) VALUES($1,$2,$3,$4,$5) RETURNING id,status",
    [req.user.id,method,sender,transactionId,amount]);
  res.status(201).json({ ok: true, payment: r.rows[0] });
});
app.post("/api/client/connections", auth, async (req, res) => {
  const name=requiredString(req.body.name,100), phone=cleanPhone(req.body.phone), address=requiredString(req.body.address,1000), pkg=requiredString(req.body.packageName,80);
  if (name.length<2 || phone.length<10 || address.length<5 || !["15 Mbps","30 Mbps","50 Mbps","100 Mbps"].includes(pkg))
    return res.status(400).json({ error: "সঠিক তথ্য দিয়ে আবেদন পূরণ করুন।" });
  await pool.query("INSERT INTO connection_requests(user_id,name,phone,address,package_name) VALUES($1,$2,$3,$4,$5)",
    [req.user.role==="client"?req.user.id:null,name,phone,address,pkg]);
  res.status(201).json({ ok:true });
});
app.post("/api/client/complaints", auth, async (req, res) => {
  const phone=cleanPhone(req.body.phone), category=requiredString(req.body.category,80), details=requiredString(req.body.details,2000);
  if (phone.length<10 || !["ইন্টারনেট চলছে না","স্পিড কম","বিল সংক্রান্ত সমস্যা","অন্যান্য"].includes(category) || details.length<4)
    return res.status(400).json({ error:"সঠিক তথ্য দিয়ে অভিযোগ লিখুন।" });
  await pool.query("INSERT INTO complaints(user_id,phone,category,details) VALUES($1,$2,$3,$4)",
    [req.user.role==="client"?req.user.id:null,phone,category,details]);
  res.status(201).json({ ok:true });
});

// Admin APIs
app.get("/api/admin/overview", auth, adminOnly, async (req,res) => {
  const [users,payments,connections,complaints] = await Promise.all([
    pool.query("SELECT id,phone,name,package_name,monthly_bill,status,created_at FROM users WHERE role='client' ORDER BY id DESC"),
    pool.query("SELECT p.id,p.method,p.sender_phone,p.transaction_id,p.amount,p.status,p.created_at,u.phone AS customer_phone FROM payments p JOIN users u ON u.id=p.user_id ORDER BY p.id DESC LIMIT 100"),
    pool.query("SELECT * FROM connection_requests ORDER BY id DESC LIMIT 100"),
    pool.query("SELECT * FROM complaints ORDER BY id DESC LIMIT 100")
  ]);
  res.json({users:users.rows,payments:payments.rows,connections:connections.rows,complaints:complaints.rows});
});
app.post("/api/admin/clients", auth, adminOnly, async (req,res) => {
  const phone=cleanPhone(req.body.phone), name=requiredString(req.body.name,100), password=requiredString(req.body.password,200);
  const packageName=requiredString(req.body.packageName,80), monthlyBill=Number(req.body.monthlyBill);
  if(phone.length<10 || name.length<2 || password.length<10 || !["15 Mbps","30 Mbps","50 Mbps","100 Mbps"].includes(packageName) || !Number.isInteger(monthlyBill) || monthlyBill<0 || monthlyBill>1000000)
    return res.status(400).json({error:"সঠিক তথ্য দিন। পাসওয়ার্ড অন্তত ১০ অক্ষরের হতে হবে।"});
  try {
    const hash=await bcrypt.hash(password,12);
    const r=await pool.query("INSERT INTO users(phone,name,password_hash,role,package_name,monthly_bill) VALUES($1,$2,$3,'client',$4,$5) RETURNING id,phone,name,package_name,monthly_bill",
      [phone,name,hash,packageName,monthlyBill]);
    res.status(201).json({user:r.rows[0]});
  } catch(e) {
    if(e.code==="23505") return res.status(409).json({error:"এই ফোন নম্বর দিয়ে অ্যাকাউন্ট আগে থেকেই আছে।"});
    console.error(e);res.status(500).json({error:"গ্রাহক তৈরি করা যায়নি।"});
  }
});
app.patch("/api/admin/clients/:id", auth, adminOnly, async (req,res) => {
  const id=Number(req.params.id), monthlyBill=Number(req.body.monthlyBill), packageName=requiredString(req.body.packageName,80), status=requiredString(req.body.status,20);
  if(!Number.isInteger(id)||id<1||!Number.isInteger(monthlyBill)||monthlyBill<0||monthlyBill>1000000||!["15 Mbps","30 Mbps","50 Mbps","100 Mbps"].includes(packageName)||!["active","suspended"].includes(status))
    return res.status(400).json({error:"বিল, প্যাকেজ বা স্ট্যাটাস সঠিক নয়।"});
  const r=await pool.query("UPDATE users SET monthly_bill=$1,package_name=$2,status=$3 WHERE id=$4 AND role='client' RETURNING id,phone,name,package_name,monthly_bill,status",
    [monthlyBill,packageName,status,id]);
  if(!r.rowCount)return res.status(404).json({error:"গ্রাহক পাওয়া যায়নি।"});
  res.json({user:r.rows[0]});
});
app.patch("/api/admin/payments/:id", auth, adminOnly, async (req,res) => {
  const status=requiredString(req.body.status,20), id=Number(req.params.id);
  if(!Number.isInteger(id)||!["approved","rejected"].includes(status))return res.status(400).json({error:"অবস্থা সঠিক নয়।"});
  const r=await pool.query("UPDATE payments SET status=$1,reviewed_at=NOW(),reviewed_by=$2 WHERE id=$3 RETURNING id,status",[status,req.user.id,id]);
  if(!r.rowCount)return res.status(404).json({error:"পেমেন্ট পাওয়া যায়নি।"});
  res.json({payment:r.rows[0]});
});
app.patch("/api/admin/connections/:id", auth, adminOnly, async (req,res) => {
  const status=requiredString(req.body.status,20), id=Number(req.params.id);
  if(!Number.isInteger(id)||!["pending","contacted","completed","rejected"].includes(status))return res.status(400).json({error:"অবস্থা সঠিক নয়।"});
  const r=await pool.query("UPDATE connection_requests SET status=$1 WHERE id=$2 RETURNING id,status",[status,id]);
  if(!r.rowCount)return res.status(404).json({error:"আবেদন পাওয়া যায়নি।"});
  res.json({connection:r.rows[0]});
});
app.patch("/api/admin/complaints/:id", auth, adminOnly, async (req,res) => {
  const status=requiredString(req.body.status,20), id=Number(req.params.id);
  if(!Number.isInteger(id)||!["open","in_progress","resolved"].includes(status))return res.status(400).json({error:"অবস্থা সঠিক নয়।"});
  const r=await pool.query("UPDATE complaints SET status=$1 WHERE id=$2 RETURNING id,status",[status,id]);
  if(!r.rowCount)return res.status(404).json({error:"অভিযোগ পাওয়া যায়নি।"});
  res.json({complaint:r.rows[0]});
});

app.get("*", (req,res) => res.sendFile(path.join(__dirname,"public","index.html")));
initDb().then(()=>app.listen(PORT,()=>console.log(`Dhamrai Net running on port ${PORT}`)))
  .catch(e=>{console.error("Database initialization failed:",e);process.exit(1);});
