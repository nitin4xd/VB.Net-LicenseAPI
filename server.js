const express = require("express");
const session = require("express-session");
const bcrypt = require("bcrypt");
const path = require("path");
const crypto = require("crypto");
const dotenv = require("dotenv");
const { createClient } = require("@supabase/supabase-js");

dotenv.config();

const app = express();

// Render/other reverse proxies terminate HTTPS before forwarding to Node.
// Trust the first proxy so secure session cookies work correctly in production.
if (process.env.NODE_ENV === "production") {
    app.set("trust proxy", 1);
}
const PORT = process.env.PORT || 3000;

const centralSupabase = createClient(
    process.env.LIFAFA_SUPABASE_URL,
    process.env.LIFAFA_SUPABASE_SECRET_KEY
);


async function verifySoftwareLogin(email, password) {
    const { data: user, error } = await centralSupabase
        .from("software_users")
        .select("id,email,password_hash")
        .eq("email", String(email).trim().toLowerCase())
        .maybeSingle();

    if (error || !user) {
        return null;
    }

    const passwordMatch = await bcrypt.compare(
        password,
        user.password_hash
    );

    if (!passwordMatch) {
        return null;
    }

    return {
        id: user.id,
        email: user.email
    };
}


app.use(express.json({ limit: "20kb" }));
app.use(express.urlencoded({ extended: true, limit: "20kb" }));

app.use(
    session({
        secret: process.env.SESSION_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            sameSite: "lax",
            maxAge: 24 * 60 * 60 * 1000
        }
    })
);


function requireLogin(req, res, next) {
    if (!req.session.user) {
        return res.redirect("/");
    }

    next();
}

app.get("/", (req, res) => {
    if (req.session.user) {
        return res.redirect("/dashboard");
    }

    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Main Login</title>
<style>
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: linear-gradient(135deg, #0f172a, #1e3a8a);
    min-height: 100vh;
    display: flex;
    justify-content: center;
    align-items: center;
}
.login-box {
    width: 400px;
    max-width: 92%;
    background: white;
    padding: 40px;
    border-radius: 18px;
    box-shadow: 0 20px 50px rgba(0,0,0,0.25);
}
.logo {
    width: 70px;
    height: 70px;
    margin: 0 auto 20px;
    background: #2563eb;
    color: white;
    border-radius: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 28px;
    font-weight: bold;
}
h1 {
    text-align: center;
    margin: 0;
    color: #0f172a;
}
.subtitle {
    text-align: center;
    color: #64748b;
    margin: 10px 0 30px;
}
input {
    width: 100%;
    padding: 14px;
    margin-bottom: 16px;
    border: 1px solid #cbd5e1;
    border-radius: 9px;
    font-size: 15px;
    outline: none;
}
input:focus {
    border-color: #2563eb;
}
button {
    width: 100%;
    padding: 14px;
    border: 0;
    border-radius: 9px;
    background: #2563eb;
    color: white;
    font-size: 16px;
    cursor: pointer;
}
button:hover {
    background: #1d4ed8;
}
</style>
</head>
<body>
<div class="login-box">
<div class="logo">CL</div>
<h1>Main Login</h1>
<div class="subtitle">Central License Manager</div>
<form method="POST" action="/login">
<input type="email" name="email" placeholder="Email" required autofocus>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>
    `);
});


app.post("/login", async (req, res) => {
    try {
        const { email, password } = req.body;

        const { data: user, error } = await centralSupabase
            .from("central_users")
            .select("id,email,password_hash")
            .eq("email", String(email).trim().toLowerCase())
            .maybeSingle();

        if (error || !user) {
            return res.send(`
<script>
alert("Invalid email or password");
window.location.href="/";
</script>
            `);
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.send(`
<script>
alert("Invalid email or password");
window.location.href="/";
</script>
            `);
        }

        req.session.user = {
            id: user.id,
            email: user.email
        };

        res.redirect("/dashboard");

    } catch (error) {
        res.status(500).send(`
<script>
alert("Unable to login");
window.location.href="/";
</script>
        `);
    }
});


app.get("/dashboard", requireLogin, (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Central License Manager</title>
<style>
* {
    box-sizing: border-box;
}
body {
    margin: 0;
    font-family: Arial, sans-serif;
    background: #f1f5f9;
    color: #0f172a;
}
.header {
    background: #0f172a;
    color: white;
    padding: 18px 35px;
    display: flex;
    justify-content: space-between;
    align-items: center;
}
.header-title {
    font-size: 21px;
    font-weight: bold;
}
.header-right {
    display: flex;
    align-items: center;
    gap: 18px;
}
.user-email {
    color: #cbd5e1;
    font-size: 14px;
}

.change-password {
    color: white;
    text-decoration: none;
    background: #2563eb;
    padding: 9px 17px;
    border-radius: 7px;
}

.logout {
    color: white;
    text-decoration: none;
    background: #dc2626;
    padding: 9px 17px;
    border-radius: 7px;
}
.container {
    max-width: 1200px;
    margin: auto;
    padding: 40px 25px;
}
.welcome {
    margin-bottom: 30px;
}
.welcome h1 {
    margin: 0 0 8px;
    font-size: 30px;
}
.welcome p {
    margin: 0;
    color: #64748b;
}
.projects {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 25px;
}
.project {
    background: white;
    border-radius: 16px;
    padding: 30px;
    box-shadow: 0 8px 25px rgba(15,23,42,0.08);
    border: 1px solid #e2e8f0;
}
.project-icon {
    width: 60px;
    height: 60px;
    border-radius: 14px;
    background: #dbeafe;
    color: #2563eb;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 22px;
    font-weight: bold;
    margin-bottom: 20px;
}
.project h2 {
    margin: 0 0 10px;
    font-size: 21px;
}
.project p {
    color: #64748b;
    min-height: 42px;
    line-height: 1.5;
}
.project button {
    width: 100%;
    padding: 13px;
    margin-top: 15px;
    border: 0;
    border-radius: 8px;
    background: #2563eb;
    color: white;
    font-size: 15px;
    cursor: pointer;
}
.project button:hover {
    background: #1d4ed8;
}
.status {
    display: inline-block;
    margin-top: 12px;
    padding: 5px 10px;
    border-radius: 20px;
    background: #dcfce7;
    color: #166534;
    font-size: 12px;
    font-weight: bold;
}
.footer {
    text-align: center;
    color: #94a3b8;
    margin-top: 50px;
    font-size: 13px;
}
</style>
</head>
<body>

<div class="header">
<div class="header-title">Central License Manager</div>
<div class="header-right">
<div class="user-email">${req.session.user.email}</div>
<a class="change-password" href="/change-password">Change Password</a>
<a class="change-password" href="/software-password">Software Password</a>
<a class="logout" href="/logout">Logout</a>
</div>
</div>

<div class="container">

<div class="welcome">
<h1>Project Dashboard</h1>
<p>Apne License Management Project ko select karein.</p>
</div>

<div class="projects">

<div class="project">
<div class="project-icon">LP</div>
<h2>Lifafa Printing Software</h2>
<p>Lifafa Printing Software ka existing License Management System.</p>
<span class="status">ACTIVE</span>
<button onclick="location.href='/project/lifafa'">Open License Manager</button>
</div>

<div class="project">
<div class="project-icon">VB</div>
<h2>VB.NET Software</h2>
<p>VB.NET Software ka existing License Management System.</p>
<span class="status">ACTIVE</span>
<button onclick="location.href='/project/vbnet'">Open License Manager</button>
</div>

</div>

<div class="footer">
Central License Manager
</div>

</div>
</body>
</html>
    `);
});


app.get("/software-password", requireLogin, (req, res) => {
    res.send(`
<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Software Common Login</title>
<style>body{font-family:Arial;background:#f1f5f9;margin:0}.box{max-width:520px;margin:55px auto;background:#fff;padding:28px;border-radius:14px;box-shadow:0 10px 30px #0002}h2{margin-top:0;color:#0f172a}label{display:block;margin:15px 0 6px;font-weight:bold}input{width:100%;box-sizing:border-box;padding:12px;border:1px solid #cbd5e1;border-radius:8px}button,a.btn{display:inline-block;margin-top:20px;padding:11px 18px;border:0;border-radius:8px;text-decoration:none;cursor:pointer}button{background:#2563eb;color:white}.btn{background:#64748b;color:white;margin-left:8px}.note{color:#64748b;font-size:13px;line-height:1.5}</style></head><body>
<div class="box"><h2>Software Common Login</h2>
<p class="note">Software Username fixed rahega. Yahan se Lifafa Printing aur VB.NET License Manager ka common Software Password change hoga.</p>
<form method="POST" action="/software-password">
<label>Software Username</label><input type="text" name="currentUsername" placeholder="Current software username" required>
<label>Current Software Password</label><input type="password" name="currentPassword" required>
<label>New Software Password</label><input type="password" name="newPassword" minlength="4" required>
<label>Confirm New Password</label><input type="password" name="confirmPassword" minlength="4" required>
<button type="submit">Change Software Password</button><a class="btn" href="/dashboard">Back</a>
</form></div></body></html>`);
});

app.post("/software-password", requireLogin, async (req, res) => {
    try {
        const { currentUsername, currentPassword, newPassword, confirmPassword } = req.body;
        const user = await verifySoftwareLogin(currentUsername, currentPassword);
        if (!user) return res.send(`<script>alert("Current software username or password is incorrect");location.href="/software-password";</script>`);
        if (!newPassword || newPassword.length < 4) return res.send(`<script>alert("New password must be at least 4 characters");location.href="/software-password";</script>`);
        if (newPassword !== confirmPassword) return res.send(`<script>alert("New password and confirm password do not match");location.href="/software-password";</script>`);
        const newHash = await bcrypt.hash(newPassword, 12);
        const { error } = await centralSupabase.from("software_users").update({
            password_hash: newHash,
            updated_at: new Date().toISOString()
        }).eq("id", user.id);
        if (error) throw error;
        return res.send(`<script>alert("Common Software Password changed successfully");location.href="/dashboard";</script>`);
    } catch (e) {
        console.error("Software login change error:", e);
        return res.send(`<script>alert("Unable to change software login");location.href="/software-password";</script>`);
    }
});

app.get("/change-password", requireLogin, (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Change Password</title>
<style>
*{box-sizing:border-box}
body{
margin:0;
font-family:Arial,sans-serif;
background:#f1f5f9;
min-height:100vh;
display:flex;
align-items:center;
justify-content:center;
}
.box{
width:420px;
max-width:92%;
background:white;
padding:35px;
border-radius:16px;
box-shadow:0 10px 35px rgba(0,0,0,.12);
}
h2{
margin:0 0 8px;
color:#0f172a;
}
.email{
color:#64748b;
font-size:14px;
margin-bottom:25px;
}
label{
display:block;
font-size:13px;
font-weight:bold;
margin-bottom:6px;
}
input{
width:100%;
padding:12px;
border:1px solid #cbd5e1;
border-radius:8px;
font-size:15px;
margin-bottom:17px;
}
button{
width:100%;
padding:12px;
border:0;
border-radius:8px;
background:#2563eb;
color:white;
font-size:15px;
cursor:pointer;
}
.back{
display:block;
text-align:center;
margin-top:18px;
color:#2563eb;
text-decoration:none;
}
</style>
</head>
<body>

<div class="box">

<h2>Change Password</h2>
<div class="email">${req.session.user.email}</div>

<form method="POST" action="/change-password">

<label>Current Password</label>
<input type="password" name="currentPassword" required>

<label>New Password</label>
<input type="password" name="newPassword" minlength="5" required>

<label>Confirm New Password</label>
<input type="password" name="confirmPassword" minlength="5" required>

<button type="submit">Change Password</button>

</form>

<a class="back" href="/dashboard">Back to Dashboard</a>

</div>

</body>
</html>
    `);
});


app.post("/change-password", requireLogin, async (req, res) => {
    try {
        const { currentPassword, newPassword, confirmPassword } = req.body;

        if (!currentPassword || !newPassword || !confirmPassword) {
            return res.send(`
<script>
alert("All fields are required");
window.location.href="/change-password";
</script>
            `);
        }

        if (newPassword.length < 5) {
            return res.send(`
<script>
alert("New password must be at least 5 characters");
window.location.href="/change-password";
</script>
            `);
        }

        if (newPassword !== confirmPassword) {
            return res.send(`
<script>
alert("New password and confirm password do not match");
window.location.href="/change-password";
</script>
            `);
        }

        const { data: user, error } = await centralSupabase
            .from("central_users")
            .select("id,email,password_hash")
            .eq("email", String(req.session.user.email).trim().toLowerCase())
            .maybeSingle();

        if (error || !user) {
            return res.send(`
<script>
alert("User not found");
window.location.href="/change-password";
</script>
            `);
        }

        const passwordMatch = await bcrypt.compare(
            currentPassword,
            user.password_hash
        );

        if (!passwordMatch) {
            return res.send(`
<script>
alert("Current password is incorrect");
window.location.href="/change-password";
</script>
            `);
        }

        if (currentPassword === newPassword) {
            return res.send(`
<script>
alert("New password must be different from current password");
window.location.href="/change-password";
</script>
            `);
        }

        const newHash = await bcrypt.hash(newPassword, 12);

        const { error: updateError } = await centralSupabase
            .from("central_users")
            .update({
                password_hash: newHash,
                updated_at: new Date().toISOString()
            })
            .eq("id", user.id);

        if (updateError) {
            return res.send(`
<script>
alert("Unable to change password");
window.location.href="/change-password";
</script>
            `);
        }

        req.session.destroy(() => {
            res.send(`
<script>
alert("Password changed successfully. Please login with your new password.");
window.location.href="/";
</script>
            `);
        });

    } catch (error) {
        res.status(500).send(`
<script>
alert("Unable to change password");
window.location.href="/change-password";
</script>
        `);
    }
});


app.post("/project/lifafa/software-login", requireLogin, async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await verifySoftwareLogin(email, password);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        req.session.softwareUser = {
            id: user.id,
            email: user.email
        };

        res.json({
            success: true,
            email: user.email
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to login"
        });
    }
});


// Public Lifafa client endpoint. The desktop app uses this route for online
// activation/checks; admin CRUD routes below remain protected by login.
app.post("/api/lifafa/license-check", async (req, res) => {
    try {
        const licenseKey = String(req.body?.license_key || "").trim();
        const deviceId = String(req.body?.device_id || "").trim();
        const action = String(req.body?.action || "check").trim().toLowerCase();
        const deviceName = String(req.body?.device_name || "").trim() || null;
        const motherboardId = req.body?.motherboard_id ? String(req.body.motherboard_id) : null;
        const hardwareFingerprint = req.body?.hardware_fingerprint ? String(req.body.hardware_fingerprint) : null;

        if (!licenseKey || !deviceId) {
            return res.status(400).json({ success: false, status: "invalid", message: "License key and device ID are required." });
        }

        const { data: license, error: licenseError } = await centralSupabase
            .from("licenses")
            .select("id,license_key,status,expires_at,max_devices")
            .eq("license_key", licenseKey)
            .maybeSingle();

        if (licenseError) throw licenseError;
        if (!license) return res.json({ success: false, status: "invalid", message: "Invalid license key." });
        if (String(license.status || "").toLowerCase() !== "active") {
            return res.json({ success: false, status: "inactive", message: "License is inactive." });
        }
        if (license.expires_at && new Date(license.expires_at).getTime() < Date.now()) {
            return res.json({ success: false, status: "expired", message: "License has expired." });
        }

        const { data: existing, error: existingError } = await centralSupabase
            .from("license_devices")
            .select("id,is_active")
            .eq("license_id", license.id)
            .eq("device_id", deviceId)
            .maybeSingle();
        if (existingError) throw existingError;

        if (existing && existing.is_active) {
            await centralSupabase.from("license_devices").update({
                device_name: deviceName,
                motherboard_id: motherboardId,
                hardware_fingerprint: hardwareFingerprint,
                last_check: new Date().toISOString()
            }).eq("id", existing.id);
            return res.json({ success: true, status: "active", message: "License active." });
        }

        if (action !== "activate") {
            return res.json({ success: false, status: "not_activated", message: "This device is not activated for this license." });
        }

        const { data: activeDevices, error: devicesError } = await centralSupabase
            .from("license_devices")
            .select("id")
            .eq("license_id", license.id)
            .eq("is_active", true);
        if (devicesError) throw devicesError;

        const maxDevices = Math.max(1, Number(license.max_devices) || 1);
        if ((activeDevices || []).length >= maxDevices) {
            return res.json({ success: false, status: "device_limit", message: "Maximum device limit reached." });
        }

        if (existing) {
            const { error } = await centralSupabase.from("license_devices").update({
                is_active: true,
                device_name: deviceName,
                motherboard_id: motherboardId,
                hardware_fingerprint: hardwareFingerprint,
                activated_at: new Date().toISOString(),
                last_check: new Date().toISOString()
            }).eq("id", existing.id);
            if (error) throw error;
        } else {
            const { error } = await centralSupabase.from("license_devices").insert({
                license_id: license.id,
                device_id: deviceId,
                device_name: deviceName,
                motherboard_id: motherboardId,
                hardware_fingerprint: hardwareFingerprint,
                is_active: true,
                activated_at: new Date().toISOString(),
                last_check: new Date().toISOString()
            });
            if (error) throw error;
        }

        return res.json({ success: true, status: "active", activated: true, message: "License activated successfully." });
    } catch (error) {
        console.error("Lifafa client license-check error:", error);
        return res.status(500).json({ success: false, status: "server_error", message: "License server error." });
    }
});

app.get("/project/lifafa/api/licenses", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const { data, error } = await centralSupabase
            .from("licenses")
            .select("id,license_key,client_name,status,expires_at,max_devices,created_at")
            .order("created_at", { ascending: false });

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        res.json({
            success: true,
            licenses: data || []
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to load licenses"
        });
    }
});


app.post("/project/lifafa/api/licenses", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const clientName = String(req.body.client_name || "").trim();
        const expiresAt = req.body.expires_at || null;
        const maxDevices = Number(req.body.max_devices);

        if (!clientName) {
            return res.status(400).json({
                success: false,
                message: "Customer name is required"
            });
        }

        if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) {
            return res.status(400).json({
                success: false,
                message: "Max devices must be between 1 and 100"
            });
        }

        const { data: existing } = await centralSupabase
            .from("licenses")
            .select("id,client_name");

        const duplicate = (existing || []).some(item =>
            String(item.client_name || "").trim().toLowerCase() ===
            clientName.toLowerCase()
        );

        if (duplicate) {
            return res.status(409).json({
                success: false,
                message: "This customer already has a license"
            });
        }

        const bytes = require("crypto").randomBytes(8);
        const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
        let random = "";

        for (const byte of bytes) {
            random += chars[byte % chars.length];
        }

        const licenseKey =
            `LF-${random.slice(0, 4)}-${random.slice(4, 8)}`;

        const { data, error } = await centralSupabase
            .from("licenses")
            .insert({
                license_key: licenseKey,
                client_name: clientName,
                status: "active",
                expires_at: expiresAt,
                max_devices: maxDevices
            })
            .select("*")
            .single();

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        res.json({
            success: true,
            license: data
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to generate license"
        });
    }
});


app.patch("/project/lifafa/api/licenses/:licenseId", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const licenseId = String(req.params.licenseId || "").trim();
        const clientName = String(req.body.client_name || "").trim();
        const expiresAt = req.body.expires_at || null;
        const maxDevices = Number(req.body.max_devices);

        if (!licenseId) {
            return res.status(400).json({
                success: false,
                message: "Invalid license"
            });
        }

        if (!clientName) {
            return res.status(400).json({
                success: false,
                message: "Customer name is required"
            });
        }

        if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) {
            return res.status(400).json({
                success: false,
                message: "Max devices must be between 1 and 100"
            });
        }

        const { data: existingCustomers, error: checkError } = await centralSupabase
            .from("licenses")
            .select("id,client_name");

        if (checkError) {
            return res.status(500).json({
                success: false,
                message: checkError.message
            });
        }

        const duplicate = (existingCustomers || []).some(item =>
            String(item.id) !== licenseId &&
            String(item.client_name || "").trim().toLowerCase() ===
            clientName.toLowerCase()
        );

        if (duplicate) {
            return res.status(409).json({
                success: false,
                message: "This customer already has a license"
            });
        }

        const { data: current, error: readError } = await centralSupabase
            .from("licenses")
            .select("status")
            .eq("id", licenseId)
            .single();

        if (readError || !current) {
            return res.status(404).json({
                success: false,
                message: "License not found"
            });
        }

        const currentStatus = String(current.status || "").toLowerCase();

        let nextStatus = currentStatus;

        if (currentStatus !== "inactive") {
            nextStatus = expiresAt && new Date(expiresAt).getTime() < Date.now()
                ? "expired"
                : "active";
        }

        const { data, error } = await centralSupabase
            .from("licenses")
            .update({
                client_name: clientName,
                expires_at: expiresAt,
                max_devices: maxDevices,
                status: nextStatus
            })
            .eq("id", licenseId)
            .select("*")
            .single();

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        res.json({
            success: true,
            license: data
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to update license"
        });
    }
});


app.patch("/project/lifafa/api/licenses/:licenseId/status", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const licenseId = String(req.params.licenseId || "").trim();
        const requestedStatus = String(req.body.status || "").trim().toLowerCase();

        if (!licenseId) {
            return res.status(400).json({
                success: false,
                message: "Invalid license"
            });
        }

        if (!["active", "inactive"].includes(requestedStatus)) {
            return res.status(400).json({
                success: false,
                message: "Invalid status"
            });
        }

        const { data: license, error: readError } = await centralSupabase
            .from("licenses")
            .select("id,status,expires_at")
            .eq("id", licenseId)
            .single();

        if (readError || !license) {
            return res.status(404).json({
                success: false,
                message: "License not found"
            });
        }

        let nextStatus = requestedStatus;

        if (
            requestedStatus === "active" &&
            license.expires_at &&
            new Date(license.expires_at).getTime() <= Date.now()
        ) {
            nextStatus = "expired";
        }

        const { data, error } = await centralSupabase
            .from("licenses")
            .update({
                status: nextStatus
            })
            .eq("id", licenseId)
            .select("id,status,expires_at")
            .single();

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        if (nextStatus === "expired") {
            return res.status(409).json({
                success: false,
                status: "expired",
                message: "Expired license cannot be activated. Extend the expiry date first."
            });
        }

        res.json({
            success: true,
            license: data
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to change license status"
        });
    }
});


app.get("/project/lifafa/api/licenses/:licenseId/devices", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const licenseId = String(req.params.licenseId || "").trim();

        if (!licenseId) {
            return res.status(400).json({
                success: false,
                message: "Invalid license"
            });
        }

        const { data, error } = await centralSupabase
            .from("license_devices")
            .select("id,device_id,device_name,motherboard_id,hardware_fingerprint,activated_at,last_check,is_active")
            .eq("license_id", licenseId)
            .eq("is_active", true)
            .order("activated_at", { ascending: false });

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        res.json({
            success: true,
            devices: data || []
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to load devices"
        });
    }
});


app.delete("/project/lifafa/api/devices/:deviceId", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const deviceId = req.params.deviceId;

        const { data, error } = await centralSupabase
            .from("license_devices")
            .delete()
            .eq("id", deviceId)
            .select("id");

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: "Device not found or not deleted"
            });
        }

        res.json({
            success: true,
            deletedDeviceId: data[0].id
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: error.message || "Unable to unbind device"
        });
    }
});


app.delete("/project/lifafa/api/licenses/:licenseId", requireLogin, async (req, res) => {
    if (!req.session.softwareUser) {
        return res.status(401).json({
            success: false,
            message: "Software login required"
        });
    }

    try {
        const licenseId = String(req.params.licenseId || "").trim();

        if (!licenseId) {
            return res.status(400).json({
                success: false,
                message: "Invalid license"
            });
        }

        const { data, error } = await centralSupabase
            .from("licenses")
            .delete()
            .eq("id", licenseId)
            .select("id,license_key,client_name");

        if (error) {
            return res.status(500).json({
                success: false,
                message: error.message
            });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({
                success: false,
                message: "License not found or not deleted"
            });
        }

        res.json({
            success: true,
            deletedLicense: data[0]
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to delete license"
        });
    }
});


app.get(["/project/lifafa", "/project/lifafa/"], requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "projects", "lifafa", "index.html"));
});

app.use("/project/lifafa", requireLogin, express.static(path.join(__dirname, "projects", "lifafa")));

app.get(["/project/vbnet", "/project/vbnet/"], requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "projects", "vbnet", "login.html"));
});

app.get("/project/vbnet/dashboard", requireLogin, (req, res) => {
    res.sendFile(path.join(__dirname, "projects", "vbnet", "dashboard.html"));
});

app.use("/project/vbnet", requireLogin, express.static(path.join(__dirname, "projects", "vbnet")));

const vbSupabase = createClient(
    process.env.VB_SUPABASE_URL,
    process.env.VB_SUPABASE_SECRET_KEY
);

async function requireVbAdmin(req, res, next) {
    const auth = req.headers.authorization || "";
    if (!auth.startsWith("Basic ")) {
        return res.status(401).json({ success: false, message: "Software login required" });
    }
    try {
        const decoded = Buffer.from(auth.slice(6), "base64").toString("utf8");
        const separator = decoded.indexOf(":");
        const username = separator >= 0 ? decoded.slice(0, separator).trim() : "";
        const password = separator >= 0 ? decoded.slice(separator + 1) : "";

        // IMPORTANT: VB.NET uses the common SOFTWARE login, not Main Admin login.
        // Lifafa and VB.NET therefore share software_users credentials while
        // central_users remains completely separate for the Main Login.
        const user = await verifySoftwareLogin(username, password);
        if (!user) {
            return res.status(401).json({ success: false, message: "Invalid software username or password" });
        }
        req.vbAdmin = { id: user.id, email: user.email };
        next();
    } catch (e) {
        return res.status(401).json({ success: false, message: "Invalid software username or password" });
    }
}


app.post("/project/vbnet/software-login", requireLogin, async (req, res) => {
    try {
        const { email, password } = req.body;

        const user = await verifySoftwareLogin(email, password);

        if (!user) {
            return res.status(401).json({
                success: false,
                message: "Invalid email or password"
            });
        }

        req.session.vbSoftwareUser = {
            id: user.id,
            email: user.email
        };

        res.json({
            success: true,
            email: user.email
        });

    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Unable to login"
        });
    }
});


app.get("/project/vbnet/auth", requireLogin, requireVbAdmin, (req, res) => {
    res.json({ success: true });
});

app.post("/project/vbnet/api/licenses", requireLogin, requireVbAdmin, async (req, res) => {
    try {
        const customerName = String(req.body.customer_name || "").trim();
        const expiryDate = String(req.body.expiry_date || "").trim();
        const maxDevices = Number(req.body.max_devices);
        const licenseType = String(req.body.license_type || "PC").trim().toUpperCase();
        const licenseSection = String(req.body.license_section || "Broker").trim();
        if (!licenseSection || licenseSection.length > 80) return res.status(400).json({ success: false, message: "Software section must be 1 to 80 characters" });

        if (!["PC", "USB"].includes(licenseType)) {
            return res.status(400).json({ success: false, message: "License type must be PC or USB" });
        }

        if (!customerName || customerName.length > 150) {
            return res.status(400).json({ success: false, message: "Valid customer name required" });
        }

        const { data: existingCustomers, error: customerCheckError } = await vbSupabase
            .from("licenses")
            .select("id,customer_name");

        if (customerCheckError) {
            return res.status(500).json({
                success: false,
                message: "Unable to check customer"
            });
        }

        const duplicateCustomer = (existingCustomers || []).some(item =>
            String(item.customer_name || "").trim().toLowerCase() ===
            customerName.toLowerCase()
        );

        if (duplicateCustomer) {
            return res.status(409).json({
                success: false,
                message: "This customer already has a license"
            });
        }

        if (expiryDate && !/^\d{4}-\d{2}-\d{2}$/.test(expiryDate)) {
            return res.status(400).json({ success: false, message: "Valid expiry date required" });
        }

        if (!Number.isInteger(maxDevices) || maxDevices < 1 || maxDevices > 100) {
            return res.status(400).json({ success: false, message: "Max devices must be between 1 and 100" });
        }

        let created = null;

        for (let attempt = 0; attempt < 5 && !created; attempt++) {
            const year = new Date().getFullYear();
            const random = Math.random().toString(36).slice(2, 8).toUpperCase();
            const licenseKey = `VB-${year}-${random}`;
            const { data, error } = await vbSupabase
                .from("licenses")
                .insert({
                    license_key: licenseKey,
                    customer_name: customerName,
                    license_section: licenseSection,
                    status: "ACTIVE",
                    expiry_date: expiryDate || null,
                    max_devices: maxDevices,
                    license_type: licenseType,
                    usb_rebind_allowed: licenseType === "USB" ? true : false
                })
                .select("*")
                .single();

            if (!error) {
                created = data;
                break;
            }

            if (error.code !== "23505") {
                return res.status(500).json({ success: false, message: error.message || "Unable to generate license" });
            }
        }

        if (!created) {
            return res.status(500).json({ success: false, message: "Unable to generate unique license key" });
        }

        res.json({ success: true, license: created });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message || "Server error" });
    }
});

app.patch("/project/vbnet/api/licenses/:licenseId", requireLogin, requireVbAdmin, async (req, res) => {
    const licenseId = req.params.licenseId;

    if (!/^\d+$/.test(licenseId)) {
        return res.status(400).json({ success: false, message: "Invalid license ID" });
    }

    const updates = {};

    if (req.body.license_section !== undefined) {
        const value = String(req.body.license_section).trim();
        if (!value || value.length > 80) return res.status(400).json({ success: false, message: "Software section must be 1 to 80 characters" });
        updates.license_section = value;
    }

    if (req.body.license_type !== undefined) {
        const value = String(req.body.license_type).trim().toUpperCase();
        if (!["PC", "USB"].includes(value)) return res.status(400).json({ success: false, message: "Invalid license type" });
        updates.license_type = value;
        // Max devices remains admin-configurable for both PC and USB licenses.
    }

    if (req.body.customer_name !== undefined) {
    const value = String(req.body.customer_name).trim();

    if (!value || value.length > 150) {
        return res.status(400).json({
            success: false,
            message: "Invalid customer name"
        });
    }

    const { data: existingCustomers, error: customerCheckError } = await vbSupabase
        .from("licenses")
        .select("id,customer_name");

    if (customerCheckError) {
        return res.status(500).json({
            success: false,
            message: "Unable to check customer"
        });
    }

    const duplicateCustomer = (existingCustomers || []).some(item =>
        Number(item.id) !== Number(licenseId) &&
        String(item.customer_name || "").trim().toLowerCase() ===
        value.toLowerCase()
    );

    if (duplicateCustomer) {
        return res.status(409).json({
            success: false,
            message: "This customer already has a license"
        });
    }

    updates.customer_name = value;
}

    if (req.body.expiry_date !== undefined) {
        const value = String(req.body.expiry_date).trim();

        if (value === "") {
            updates.expiry_date = null;
        } else {
            if (!/^\d{4}-\d{2}-\d{2}$/.test(value)) {
                return res.status(400).json({
                    success: false,
                    message: "Invalid expiry date"
                });
            }

            updates.expiry_date = value;
        }
    }

    if (req.body.max_devices !== undefined) {
        const value = Number(req.body.max_devices);
        if (!Number.isInteger(value) || value < 1 || value > 100) return res.status(400).json({ success: false, message: "Invalid max devices" });
        updates.max_devices = value;
    }

    if (req.body.status !== undefined) {
        const value = String(req.body.status).toUpperCase();
        if (!["ACTIVE", "INACTIVE", "EXPIRED"].includes(value)) return res.status(400).json({ success: false, message: "Invalid status" });
        updates.status = value;
    }

    if (Object.keys(updates).length === 0) {
        return res.status(400).json({ success: false, message: "No changes supplied" });
    }

    try {
        if (updates.expiry_date !== undefined && updates.status === undefined) {
            const { data: currentLicense, error: currentError } = await vbSupabase
                .from("licenses")
                .select("status")
                .eq("id", Number(licenseId))
                .single();

            if (currentError) return res.status(500).json({ success: false, message: currentError.message || "Unable to load license" });

            const now = new Date();
            const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
            if (String(currentLicense.status).toUpperCase() === "EXPIRED" && updates.expiry_date >= today) updates.status = "ACTIVE";
            if (String(currentLicense.status).toUpperCase() === "ACTIVE" && updates.expiry_date < today) updates.status = "EXPIRED";
        }

        const { data, error } = await vbSupabase
            .from("licenses")
            .update(updates)
            .eq("id", Number(licenseId))
            .select("*")
            .single();

        if (error) return res.status(500).json({ success: false, message: error.message || "Unable to update license" });
        res.json({ success: true, license: data });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message || "Server error" });
    }
});

app.delete("/project/vbnet/api/licenses/:licenseId", requireLogin, requireVbAdmin, async (req, res) => {
    const licenseId = req.params.licenseId;

    if (!/^\d+$/.test(licenseId)) {
        return res.status(400).json({ success: false, message: "Invalid license ID" });
    }

    try {
        const { error: deviceError } = await vbSupabase.from("license_devices").delete().eq("license_id", Number(licenseId));
        if (deviceError) return res.status(500).json({ success: false, message: deviceError.message || "Unable to remove device bindings" });

        const { data, error } = await vbSupabase.from("licenses").delete().eq("id", Number(licenseId)).select("id");
        if (error) return res.status(500).json({ success: false, message: error.message || "Unable to delete license" });
        if (!data || data.length === 0) return res.status(404).json({ success: false, message: "License not found" });
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message || "Server error" });
    }
});

app.get("/project/vbnet/api/licenses", requireLogin, requireVbAdmin, async (req, res) => {
    try {
        const { data, error } = await vbSupabase
            .from("licenses")
            .select("*")
            .order("id", { ascending: false });

        if (error) {
            return res.status(500).json({ success: false, message: "Unable to load licenses" });
        }

        const now = new Date();
        const today = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, "0")}-${String(now.getDate()).padStart(2, "0")}`;
        const expiredIds = (data || []).filter(item => String(item.status).toUpperCase() === "ACTIVE" && item.expiry_date && String(item.expiry_date).slice(0, 10) < today).map(item => item.id);

        if (expiredIds.length) {
            await vbSupabase.from("licenses").update({ status: "EXPIRED" }).in("id", expiredIds);
            for (const item of data) if (expiredIds.includes(item.id)) item.status = "EXPIRED";
        }

        res.json({ success: true, licenses: data });
    } catch {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.get("/project/vbnet/api/licenses/:licenseId/devices", requireLogin, requireVbAdmin, async (req, res) => {
    const licenseId = req.params.licenseId;

    if (!/^\d+$/.test(licenseId)) {
        return res.status(400).json({ success: false, message: "Invalid license ID" });
    }

    try {
        const { data, error } = await vbSupabase
            .from("license_devices")
            .select("*")
            .eq("license_id", Number(licenseId))
            .order("id", { ascending: true });

        if (error) {
            return res.status(500).json({ success: false, message: "Unable to load devices" });
        }

        res.json({ success: true, devices: data });
    } catch {
        res.status(500).json({ success: false, message: "Server error" });
    }
});

app.delete("/project/vbnet/api/licenses/:licenseId/devices/:deviceId", requireLogin, requireVbAdmin, async (req, res) => {
    const licenseId = req.params.licenseId;
    const deviceId = req.params.deviceId;

    if (!/^\d+$/.test(licenseId) || !deviceId || deviceId.length > 200) {
        return res.status(400).json({ success: false, message: "Invalid request" });
    }

    try {
        const { data, error } = await vbSupabase
            .from("license_devices")
            .delete()
            .eq("license_id", Number(licenseId))
            .eq("device_id", deviceId)
            .select("id");

        if (error) {
            return res.status(500).json({ success: false, message: "Unable to unbind device" });
        }

        if (!data || data.length === 0) {
            return res.status(404).json({ success: false, message: "Device binding not found" });
        }

        res.json({ success: true, message: "Device unbound successfully" });
    } catch {
        res.status(500).json({ success: false, message: "Server error" });
    }
});


// ===================== VB.NET PENDRIVE LICENSE =====================
function normalizeUsbId(value) {
    return String(value || "").trim().toUpperCase().replace(/\s+/g, " ").slice(0, 500);
}

function usbHash(value) {
    return crypto.createHash("sha256").update(normalizeUsbId(value), "utf8").digest("hex");
}

async function getVbLicenseByKey(licenseKey) {
    const { data, error } = await vbSupabase
        .from("licenses")
        .select("*")
        .eq("license_key", String(licenseKey || "").trim().toUpperCase())
        .maybeSingle();
    if (error) throw error;
    return data;
}

function vbLicenseUsable(license) {
    if (!license || String(license.status).toUpperCase() !== "ACTIVE") return false;
    if (!license.expiry_date) return true;
    const today = new Date().toISOString().slice(0, 10);
    return String(license.expiry_date).slice(0, 10) >= today;
}

app.get("/project/vbnet/api/licenses/:licenseId/usb-devices", requireLogin, requireVbAdmin, async (req, res) => {
    const licenseId = req.params.licenseId;
    if (!/^\d+$/.test(licenseId)) return res.status(400).json({ success: false, message: "Invalid license ID" });
    const { data, error } = await vbSupabase.from("usb_license_devices").select("*").eq("license_id", Number(licenseId)).order("id", { ascending: true });
    if (error) return res.status(500).json({ success: false, message: error.message || "Unable to load USB bindings" });
    const { data: licenseState, error: stateError } = await vbSupabase.from("licenses").select("usb_rebind_allowed,max_devices,license_type").eq("id", Number(licenseId)).maybeSingle();
    if (stateError) return res.status(500).json({ success: false, message: stateError.message || "Unable to load pendrive authorization status" });
    const maxDevices = Math.max(1, Number(licenseState && licenseState.max_devices) || 1);
    const activeCount = (data || []).filter(x => x.is_active).length;
    res.json({ success: true, devices: data || [], rebind_allowed: !!(licenseState && licenseState.usb_rebind_allowed), max_devices: maxDevices, active_devices: activeCount, available_slots: Math.max(0, maxDevices - activeCount) });
});

app.delete("/project/vbnet/api/licenses/:licenseId/usb-devices/:bindingId", requireLogin, requireVbAdmin, async (req, res) => {
    if (!/^\d+$/.test(req.params.licenseId) || !/^\d+$/.test(req.params.bindingId)) return res.status(400).json({ success: false, message: "Invalid request" });
    const licenseId = Number(req.params.licenseId);
    const { data, error } = await vbSupabase.from("usb_license_devices").delete().eq("license_id", licenseId).eq("id", Number(req.params.bindingId)).select("id");
    if (error) return res.status(500).json({ success: false, message: error.message || "Unable to unbind pendrive" });
    if (!data || !data.length) return res.status(404).json({ success: false, message: "USB binding not found" });
    const { error: lockError } = await vbSupabase.from("licenses").update({ usb_rebind_allowed: false }).eq("id", licenseId);
    if (lockError) return res.status(500).json({ success: false, message: lockError.message || "Pendrive unbound but rebind lock could not be saved" });
    res.json({ success: true, rebind_allowed: false });
});

app.post("/project/vbnet/api/licenses/:licenseId/allow-usb-rebind", requireLogin, requireVbAdmin, async (req, res) => {
    if (!/^\d+$/.test(req.params.licenseId)) return res.status(400).json({ success: false, message: "Invalid license ID" });
    const licenseId = Number(req.params.licenseId);
    const { data: activeBindings, error: bindingError } = await vbSupabase.from("usb_license_devices").select("id").eq("license_id", licenseId).eq("is_active", true);
    if (bindingError) return res.status(500).json({ success: false, message: bindingError.message || "Unable to check pendrive binding" });
    if (activeBindings && activeBindings.length) return res.status(409).json({ success: false, message: "Unbind the current pendrive first." });
    const { data, error } = await vbSupabase.from("licenses").update({ usb_rebind_allowed: true }).eq("id", licenseId).eq("license_type", "USB").select("id").maybeSingle();
    if (error) return res.status(500).json({ success: false, message: error.message || "Unable to allow new pendrive" });
    if (!data) return res.status(404).json({ success: false, message: "USB license not found" });
    res.json({ success: true, rebind_allowed: true, message: "New pendrive activation allowed. The next pendrive activated online will be locked to this license." });
});

// First run: binds the license to the physical USB identity supplied by the VB.NET client.
app.post("/api/vbnet/usb/activate", async (req, res) => {
    try {
        const licenseKey = String(req.body.license_key || "").trim().toUpperCase();
        const physicalId = normalizeUsbId(req.body.usb_physical_id);
        const usbName = String(req.body.usb_name || "Pendrive").trim().slice(0, 150);
        if (!licenseKey || physicalId.length < 4) return res.status(400).json({ success: false, message: "License key and USB physical ID required" });
        const license = await getVbLicenseByKey(licenseKey);
        const requestedSection = String(req.body.license_section || "").trim();
        if (!requestedSection) return res.status(400).json({ success: false, message: "Software section is required" });
        if (!license || String(license.license_type || "PC").toUpperCase() !== "USB") return res.status(403).json({ success: false, message: "This is not a pendrive license" });
        if (String(license.license_section || "").trim().toLowerCase() !== requestedSection.toLowerCase()) return res.status(403).json({ success: false, message: "License belongs to " + String(license.license_section || "another") + " section, not " + requestedSection });
        if (!vbLicenseUsable(license)) return res.status(403).json({ success: false, message: "License is inactive or expired" });
        const hash = usbHash(physicalId);
        const { data: existing, error: readError } = await vbSupabase.from("usb_license_devices").select("*").eq("license_id", license.id);
        if (readError) throw readError;

        const bindings = existing || [];
        const samePendrive = bindings.find(x => x.usb_hash === hash);
        const now = new Date().toISOString();

        // An already-authorized pendrive remains valid even when the license is at capacity.
        if (samePendrive && samePendrive.is_active) {
            const { error: touchError } = await vbSupabase.from("usb_license_devices").update({ last_check: now, usb_name: usbName }).eq("id", samePendrive.id);
            if (touchError) throw touchError;
            return res.json({ success: true, activated: true, message: "Pendrive already activated", license_section: license.license_section, max_devices: Math.max(1, Number(license.max_devices) || 1) });
        }

        // Enforce the configured device limit instead of rejecting every second pendrive.
        const maxDevices = Math.max(1, Number(license.max_devices) || 1);
        const activeBindings = bindings.filter(x => x.is_active);
        if (activeBindings.length >= maxDevices) {
            return res.status(409).json({
                success: false,
                code: "USB_DEVICE_LIMIT_REACHED",
                message: `Maximum pendrive limit reached (${activeBindings.length}/${maxDevices}). Unbind a pendrive in License Manager before adding another.`,
                active_devices: activeBindings.length,
                max_devices: maxDevices
            });
        }

        // Keep the explicit admin rebind approval when all pendrives have been removed.
        // If at least one slot remains alongside an existing binding, max_devices authorizes it.
        if (activeBindings.length === 0 && license.usb_rebind_allowed !== true) {
            return res.status(403).json({ success: false, code: "USB_REBIND_LOCKED", message: "No active pendrive is bound and reactivation is locked. Use Allow New Pendrive in Central License Manager first." });
        }

        const bindingData = {
            license_id: license.id,
            usb_hash: hash,
            usb_name: usbName,
            usb_id_hint: physicalId.slice(-24),
            is_active: true,
            activated_at: now,
            last_check: now
        };

        // Reuse an inactive row for this same pendrive to respect the table's unique key.
        if (samePendrive) {
            const { error: reactivateError } = await vbSupabase.from("usb_license_devices").update(bindingData).eq("id", samePendrive.id);
            if (reactivateError) throw reactivateError;
        } else {
            const { error: insertError } = await vbSupabase.from("usb_license_devices").insert(bindingData);
            if (insertError) throw insertError;
        }

        if (license.usb_rebind_allowed === true) {
            const { error: lockError } = await vbSupabase.from("licenses").update({ usb_rebind_allowed: false }).eq("id", license.id);
            if (lockError) throw lockError;
        }
        res.json({ success: true, activated: true, message: "Pendrive activated successfully", license_section: license.license_section, active_devices: activeBindings.length + 1, max_devices: maxDevices });
    } catch (error) {
        res.status(500).json({ success: false, message: error.message || "Activation failed" });
    }
});

app.post("/api/vbnet/usb/verify", async (req, res) => {
    try {
        const licenseKey = String(req.body.license_key || "").trim().toUpperCase();
        const physicalId = normalizeUsbId(req.body.usb_physical_id);
        if (!licenseKey || physicalId.length < 4) return res.status(400).json({ success: false, valid: false, message: "License key and USB physical ID required" });
        const license = await getVbLicenseByKey(licenseKey);
        const requestedSection = String(req.body.license_section || "").trim();
        if (!requestedSection) return res.status(400).json({ success: false, valid: false, message: "Software section is required" });
        if (!license || String(license.license_type || "PC").toUpperCase() !== "USB" || !vbLicenseUsable(license)) return res.status(403).json({ success: false, valid: false, message: "License is invalid, inactive or expired" });
        if (String(license.license_section || "").trim().toLowerCase() !== requestedSection.toLowerCase()) return res.status(403).json({ success: false, valid: false, message: "License belongs to " + String(license.license_section || "another") + " section, not " + requestedSection });
        const hash = usbHash(physicalId);
        const { data: binding, error } = await vbSupabase.from("usb_license_devices").select("*").eq("license_id", license.id).eq("usb_hash", hash).eq("is_active", true).maybeSingle();
        if (error) throw error;
        if (!binding) return res.status(403).json({ success: false, valid: false, message: "Authorized pendrive not found" });
        await vbSupabase.from("usb_license_devices").update({ last_check: new Date().toISOString() }).eq("id", binding.id);
        res.json({ success: true, valid: true, customer_name: license.customer_name, expiry_date: license.expiry_date, license_section: license.license_section });
    } catch (error) {
        res.status(500).json({ success: false, valid: false, message: error.message || "Verification failed" });
    }
});

app.get("/logout", (req, res) => {
    req.session.destroy(() => {
        res.redirect("/");
    });
});

app.listen(PORT, () => {
    console.log(`Central License Manager running at http://localhost:${PORT}`);
});
