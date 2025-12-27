const express = require("express");
const mysql = require("mysql2");
const cors = require("cors");
// Add this with your other imports
const nodemailer = require("nodemailer");
const crypto = require("crypto");

const app = express();
app.use(cors());
app.use(express.json());

// ---------------- MYSQL CONNECTION ----------------
const db = mysql.createConnection({
    host: "localhost",
    user: "root",         // change if needed
    password: "Allah7273691@",         // your MySQL password
    database: "login_security"
});

db.connect(err => {
    if (err) console.log("DB Connection Error:", err);
    else console.log("Database Connected");
});

// ---------------- PASSWORD HASH ----------------
function hashPassword(password) {
    return crypto.createHash("sha256").update(password).digest("hex");
}

// ---------------- EMAIL SENDER ----------------
const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: "email.com",        // << ENTER YOUR EMAIL
        pass: ""            // << ENTER APP PASSWORD
    }
});

// Send OTP Email
function sendOTP(email, otp) {
    transporter.sendMail({
        to: email,
        subject: "Your Login OTP",
        text: `Your OTP is: ${otp} (valid for 5 minutes)`
    });
}

// ---------------- SIGN UP ----------------
app.post("/signup", (req, res) => {
    const { username, email, password,captchaValue, userCaptcha } = req.body;
    const hashed = hashPassword(password);

    if(captchaValue!== userCaptcha){
        return res.json({success: false, message:"Invalid Captcha"});
    }

    db.query("SELECT email FROM users WHERE email = ?", [email], (err, rows) => {
        if (rows.length > 0) return res.json({ success: false, message: "Email already exists" });

        db.query(
            "INSERT INTO users (username, email, password_hash, failed_attempts, locked_until, consecutive_locks) VALUES (?, ?, ?, 0, NULL, 0)",
            [username, email, hashed],
            err => {
                if (err) return res.json({ success: false, message: "Database Error" });
                res.json({ success: true, message: "Account created successfully!" });
            }
        );
    });
});

// ---------------- SIGN IN WITH ESCALATING LOCKOUT ----------------
app.post("/signin", (req, res) => {
    const { email, password, captchaValue, userCaptcha } = req.body;
    const hashed = hashPassword(password);
    const currentTime = Date.now();

    if(captchaValue!== userCaptcha){
        return res.json({success: false, message:"Invalid CaPTCHA"});
    }

    db.query("SELECT * FROM users WHERE email = ?", [email], (err, rows) => {
        if (rows.length === 0) {
            return res.json({ 
                success: false, 
                message: "User does not exist",
                attemptsLeft: null,
                failedAttempts: 0
            });
        }

        const user = rows[0];

        // Check if account is currently locked
        if (user.locked_until && currentTime < user.locked_until) {
            const remainingSeconds = Math.ceil((user.locked_until - currentTime) / 1000);
            return res.json({
                success: false,
                message: `Account locked. Please try again in ${remainingSeconds} seconds.`,
                attemptsLeft: 0,
                locked: true,
                failedAttempts: user.failed_attempts || 5,
                consecutiveLocks: user.consecutive_locks || 0
            });
        }

        // If lock time has expired, DO NOT reset failed attempts - keep them at 5
        // This is CRITICAL: After lock expires, next wrong attempt should trigger 1-minute lock
        if (user.locked_until && currentTime >= user.locked_until) {
            // IMPORTANT: Keep failed_attempts at 5, just clear the lock
            db.query("UPDATE users SET locked_until = NULL WHERE email = ?", [email], (updateErr) => {
                if (updateErr) {
                    console.error("Update error:", updateErr);
                    return res.json({ success: false, message: "Database Error" });
                }
                
                // Now handle the login attempt with failed_attempts still at 5
                handleLoginAttemptAfterLock(user, email, hashed, currentTime, res);
            });
            return;
        }

        // Handle normal login attempt (no lock or lock expired)
        handleLoginAttempt(user, email, hashed, currentTime, res);
    });
});

// Helper function to handle login attempts (for first lock scenario)
function handleLoginAttempt(user, email, hashed, currentTime, res) {
    // Check password
    if (user.password_hash === hashed) {
        // Successful login - generate OTP and send email
        const otp = crypto.randomInt(100000, 999999).toString();
        const otpExpiry = Date.now() + (5 * 60 * 1000); // 5 minutes

        // Send OTP email
        sendOTP(email, otp);

        // Store OTP in database
        db.query("UPDATE users SET otp = ?, otp_expiry = ?, failed_attempts = 0, locked_until = NULL, consecutive_locks = 0 WHERE email = ?",
            [otp, otpExpiry, email], (err) => {
                if (err) {
                    console.error("OTP storage error:", err);
                    return res.json({ success: false, message: "Database Error" });
                }

                return res.json({
                    success: true,
                    message: "Login Successful! Please check your email for OTP.",
                    attemptsLeft: 5,
                    failedAttempts: 0
                });
            });
    } else {
        // Wrong password - increment failed attempts
        let newAttempts = (user.failed_attempts || 0) + 1;
        let consecutiveLocks = user.consecutive_locks || 0;

        // Check if we need to lock the account
        if (newAttempts >= 5) {
            let lockDuration;
            let lockMessage;
            
            // Determine lock duration based on consecutive locks
            if (consecutiveLocks === 0) {
                // First lock: 30 seconds
                lockDuration = 30 * 1000; // 30 seconds
                lockMessage = "Too many failed attempts. Account locked for 30 seconds.";
                consecutiveLocks = 1;
            } else if (consecutiveLocks === 1) {
                // Second consecutive lock: 1 minute
                lockDuration = 60 * 1000; // 1 minute
                lockMessage = "Account locked again. Please wait 1 minute.";
                consecutiveLocks = 2;
            } else {
                // Third or more consecutive lock: 5 minutes
                lockDuration = 5 * 60 * 1000; // 5 minutes
                lockMessage = "Multiple lockouts detected. Account locked for 5 minutes.";
                consecutiveLocks += 1;
            }
            
            const lockTime = currentTime + lockDuration;

            db.query("UPDATE users SET failed_attempts = ?, locked_until = ?, consecutive_locks = ? WHERE email = ?",
                [newAttempts, lockTime, consecutiveLocks, email], (err) => {
                    if (err) {
                        console.error("Update error:", err);
                        return res.json({ success: false, message: "Database Error" });
                    }

                    // Send security alert email
                    transporter.sendMail({
                        to: user.email,
                        subject: "⚠ Security Alert – Suspicious Activity",
                        text: "Someone attempted to access your account 5 times with wrong password!"
                    });

                    return res.json({
                        success: false,
                        message: lockMessage,
                        attemptsLeft: 0,
                        locked: true,
                        failedAttempts: newAttempts,
                        lockDuration: lockDuration / 1000, // in seconds
                        consecutiveLocks: consecutiveLocks
                    });
                });
            return; // Prevent further execution
        } else {
            // Update failed attempts but don't lock yet
            let attemptsLeft = 5 - newAttempts;
            db.query("UPDATE users SET failed_attempts = ?, locked_until = NULL WHERE email = ?",
                [newAttempts, email], (err) => {
                    if (err) console.error("Update error:", err);
                });

            return res.json({
                success: false,
                message: `Incorrect password. ${attemptsLeft} attempt${attemptsLeft !== 1 ? 's' : ''} left.`,
                attemptsLeft: attemptsLeft,
                failedAttempts: newAttempts
            });
        }
    }
}

// Special handler for login attempts AFTER a lock has expired
function handleLoginAttemptAfterLock(user, email, hashed, currentTime, res) {
    // Check password
    if (user.password_hash === hashed) {
        // Successful login - reset all counters
        db.query("UPDATE users SET failed_attempts = 0, locked_until = NULL, consecutive_locks = 0 WHERE email = ?", 
            [email], (err) => {
                if (err) console.error("Reset error:", err);
            });
        
        return res.json({ 
            success: true, 
            message: "Login Successful!",
            attemptsLeft: 5,
            failedAttempts: 0
        });
    } else {
        // Wrong password AFTER lock expired
        // Since failed_attempts is already 5, this should trigger 1-minute lock immediately
        let consecutiveLocks = user.consecutive_locks || 0;
        let lockDuration;
        let lockMessage;
        
        // Determine lock duration based on consecutive locks
        if (consecutiveLocks === 0) {
            // This shouldn't happen, but just in case
            lockDuration = 60 * 1000; // 1 minute
            lockMessage = "Account locked for 1 minute.";
            consecutiveLocks = 1;
        } else if (consecutiveLocks === 1) {
            // Second lock: 1 minute
            lockDuration = 60 * 1000; // 1 minute
            lockMessage = "Account locked again. Please wait 1 minute.";
            consecutiveLocks = 2;
        } else {
            // Third or more lock: 5 minutes
            lockDuration = 5 * 60 * 1000; // 5 minutes
            lockMessage = "Multiple lockouts detected. Account locked for 5 minutes.";
            consecutiveLocks += 1;
        }
        
        const lockTime = currentTime + lockDuration;
        const newAttempts = 6; // Set to 6 to indicate "after lock"

        db.query("UPDATE users SET failed_attempts = ?, locked_until = ?, consecutive_locks = ? WHERE email = ?",
            [newAttempts, lockTime, consecutiveLocks, email], (err) => {
                if (err) {
                    console.error("Update error:", err);
                    return res.json({ success: false, message: "Database Error" });
                }

                return res.json({
                    success: false,
                    message: lockMessage,
                    attemptsLeft: 0,
                    locked: true,
                    failedAttempts: newAttempts,
                    lockDuration: lockDuration / 1000, // in seconds
                    consecutiveLocks: consecutiveLocks
                });
            });
    }
}

// ---------------- CHECK ATTEMPT STATUS ----------------
app.get("/check-attempts/:email", (req, res) => {
    const email = req.params.email;
    const currentTime = Date.now();
    
    db.query("SELECT failed_attempts, locked_until, consecutive_locks FROM users WHERE email = ?", 
        [email], (err, rows) => {
            if (err || rows.length === 0) {
                return res.json({ 
                    failedAttempts: 0, 
                    locked: false, 
                    consecutiveLocks: 0,
                    attemptsLeft: 5
                });
            }
            
            const user = rows[0];
            const locked = user.locked_until && currentTime < user.locked_until;
            
            let remainingSeconds = 0;
            if (locked && user.locked_until) {
                remainingSeconds = Math.ceil((user.locked_until - currentTime) / 1000);
            }
            
            // Calculate attempts left - if failed_attempts is 5 or more, show 0 attempts left
            let attemptsLeft = 0;
            if (user.failed_attempts < 5) {
                attemptsLeft = 5 - user.failed_attempts;
            }
            
            res.json({
                failedAttempts: user.failed_attempts || 0,
                locked: locked,
                consecutiveLocks: user.consecutive_locks || 0,
                attemptsLeft: attemptsLeft,
                remainingLockTime: remainingSeconds
            });
        });
});

// Add this route to your backend (after the other routes)
// ---------------- CREATE TEST ACCOUNT ----------------
app.post("/create-test-account", (req, res) => {
    const { username, email, password } = req.body;
    const hashed = hashPassword(password);

    db.query(
        "INSERT INTO users (username, email, password_hash, failed_attempts, locked_until, consecutive_locks) VALUES (?, ?, ?, 0, NULL, 0) ON DUPLICATE KEY UPDATE password_hash = ?, failed_attempts = 0, locked_until = NULL, consecutive_locks = 0",
        [username, email, hashed, hashed],
        err => {
            if (err) return res.json({ success: false, message: "Database Error: " + err.message });
            res.json({ success: true, message: "Test account created/updated!" });
        }
    );
});

// ---------------- RESET TEST ACCOUNT ----------------
app.post("/reset-test-account", (req, res) => {
    const { email } = req.body;
    
    db.query(
        "UPDATE users SET failed_attempts = 0, locked_until = NULL, consecutive_locks = 0 WHERE email = ?",
        [email],
        err => {
            if (err) return res.json({ success: false, message: "Database Error" });
            res.json({ success: true, message: "Test account reset!" });
        }
    );
});

// ---------------- GET USER STATUS ----------------
app.get("/user-status/:email", (req, res) => {
    const email = req.params.email;
    const currentTime = Date.now();

    db.query("SELECT failed_attempts, locked_until, consecutive_locks FROM users WHERE email = ?",
        [email], (err, rows) => {
            if (err || rows.length === 0) {
                return res.json({
                    exists: false,
                    failedAttempts: 0,
                    locked: false,
                    consecutiveLocks: 0,
                    attemptsLeft: 5
                });
            }

            const user = rows[0];
            const locked = user.locked_until && currentTime < user.locked_until;

            let remainingSeconds = 0;
            if (locked && user.locked_until) {
                remainingSeconds = Math.ceil((user.locked_until - currentTime) / 1000);
            }

            // Calculate attempts left
            let attemptsLeft = 0;
            if (user.failed_attempts < 5) {
                attemptsLeft = 5 - user.failed_attempts;
            }

            res.json({
                exists: true,
                failedAttempts: user.failed_attempts || 0,
                locked: locked,
                consecutiveLocks: user.consecutive_locks || 0,
                attemptsLeft: attemptsLeft,
                remainingLockTime: remainingSeconds,
                nextLockDuration: getNextLockDuration(user.consecutive_locks || 0)
            });
        });
});

// ---------------- GET ALL USERS STATUS ----------------
app.get("/all-users-status", (req, res) => {
    const currentTime = Date.now();

    db.query("SELECT username, email, failed_attempts, locked_until, consecutive_locks FROM users ORDER BY email",
        [], (err, rows) => {
            if (err) {
                return res.json({ success: false, message: "Database Error", users: [] });
            }

            const users = rows.map(user => {
                const locked = user.locked_until && currentTime < user.locked_until;

                let remainingSeconds = 0;
                if (locked && user.locked_until) {
                    remainingSeconds = Math.ceil((user.locked_until - currentTime) / 1000);
                }

                // Calculate attempts left
                let attemptsLeft = 0;
                if (user.failed_attempts < 5) {
                    attemptsLeft = 5 - user.failed_attempts;
                }

                return {
                    username: user.username,
                    email: user.email,
                    failedAttempts: user.failed_attempts || 0,
                    locked: locked,
                    consecutiveLocks: user.consecutive_locks || 0,
                    attemptsLeft: attemptsLeft,
                    remainingLockTime: remainingSeconds,
                    nextLockDuration: getNextLockDuration(user.consecutive_locks || 0)
                };
            });

            res.json({
                success: true,
                users: users,
                totalUsers: users.length
            });
        });
});

// Helper function to determine next lock duration
function getNextLockDuration(consecutiveLocks) {
    if (consecutiveLocks === 0) {
        return 30; // 30 seconds for first lock
    } else if (consecutiveLocks === 1) {
        return 60; // 1 minute for second lock
    } else {
        return 300; // 5 minutes for subsequent locks
    }
}

// ---------------- TEST ENDPOINT FOR SCENARIO 1 ----------------
app.post("/test-scenario1", (req, res) => {
    const { email } = req.body;
    const currentTime = Date.now();
    
    // Simulate the exact scenario you want to test
    db.query("SELECT * FROM users WHERE email = ?", [email], (err, rows) => {
        if (err || rows.length === 0) {
            return res.json({ success: false, message: "User not found" });
        }
        
        const user = rows[0];
        
        // Return current status
        const locked = user.locked_until && currentTime < user.locked_until;
        let remainingSeconds = 0;
        if (locked && user.locked_until) {
            remainingSeconds = Math.ceil((user.locked_until - currentTime) / 1000);
        }
        
        res.json({
            success: true,
            failedAttempts: user.failed_attempts,
            locked: locked,
            consecutiveLocks: user.consecutive_locks,
            remainingLockTime: remainingSeconds,
            status: `User has ${user.failed_attempts} failed attempts, ${locked ? 'locked' : 'not locked'}, consecutive locks: ${user.consecutive_locks}`
        });
    });
});
// ---------------- VERIFY OTP ----------------
app.post("/verify-otp", (req, res) => {
    const { email, otp } = req.body;

    db.query("SELECT otp, otp_expiry FROM users WHERE email = ?", [email], (err, rows) => {
        if (rows.length === 0) return res.json({ success: false, message: "User not found" });

        const user = rows[0];

        if (!user.otp || user.otp !== otp)
            return res.json({ success: false, message: "Invalid OTP" });

        if (Date.now() > user.otp_expiry)
            return res.json({ success: false, message: "OTP expired" });

        db.query("UPDATE users SET otp = NULL, otp_expiry = NULL WHERE email = ?", [email]);
        res.json({ success: true, message: "Login Successful!" });
    });
});


// ---------------- START SERVER ----------------

app.listen(3000, () => console.log("Server running on port 3000"));
