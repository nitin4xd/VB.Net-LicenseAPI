const express = require("express");
const dotenv = require("dotenv");
const crypto = require("crypto");
const { createClient } = require("@supabase/supabase-js");

dotenv.config();

const app = express();
app.use(express.json({ limit: "1mb" }));

const PORT = process.env.PORT || 3000;

const supabaseUrl = process.env.VB_SUPABASE_URL;
const supabaseKey = process.env.VB_SUPABASE_SECRET_KEY;

if (!supabaseUrl || !supabaseKey) {
    throw new Error("Missing VB_SUPABASE_URL or VB_SUPABASE_SECRET_KEY");
}

const vbSupabase = createClient(supabaseUrl, supabaseKey);

// --------------------------------------------------
// COMMON HELPERS
// --------------------------------------------------

function normalize(value) {
    return String(value || "").trim();
}

function normalizeSection(value) {
    const section = normalize(value).toLowerCase();

    if (section === "broker") return "Broker";
    if (section === "lewal") return "Lewal";

    return "";
}

function licenseIsUsable(license) {
    if (!license) return false;

    if (String(license.status || "").toUpperCase() !== "ACTIVE") {
        return false;
    }

    if (!license.expiry_date) return true;

    const today = new Date().toISOString().slice(0, 10);

    return String(license.expiry_date).slice(0, 10) >= today;
}

async function getLicense(licenseKey) {
    const { data, error } = await vbSupabase
        .from("licenses")
        .select("*")
        .eq("license_key", licenseKey)
        .maybeSingle();

    if (error) throw error;

    return data;
}

function reject(res, message, status = 403, code = null) {
    const result = {
        success: false,
        valid: false,
        message: message
    };

    if (code) result.code = code;

    return res.status(status).json(result);
}

function getMaxDevices(license) {
    return Math.max(1, Number(license.max_devices) || 1);
}

// --------------------------------------------------
// USB HELPERS
// --------------------------------------------------

function normalizeUsbId(value) {
    return String(value || "")
        .trim()
        .toUpperCase()
        .replace(/\s+/g, " ")
        .slice(0, 500);
}

function usbHash(value) {
    return crypto
        .createHash("sha256")
        .update(normalizeUsbId(value), "utf8")
        .digest("hex");
}

// --------------------------------------------------
// HEALTH CHECK
// --------------------------------------------------

app.get("/", (req, res) => {
    res.json({
        success: true,
        message: "VB.NET PC and USB License API is running"
    });
});

app.get("/health", (req, res) => {
    res.json({
        success: true,
        status: "healthy"
    });
});

// ==================================================
// PC LICENSE CHECK + FIRST TIME ACTIVATION
// ==================================================

app.post("/check", async (req, res) => {
    try {
        const licenseKey = normalize(req.body.license_key).toUpperCase();
        const deviceId = normalize(req.body.device_id);
        const fingerprint = normalize(req.body.hardware_fingerprint);
        const requestedSection = normalizeSection(req.body.license_section);

        if (!licenseKey || !deviceId || !fingerprint) {
            return reject(
                res,
                "License key and hardware information required",
                400
            );
        }

        if (!requestedSection) {
            return reject(res, "Invalid software section", 400);
        }

        const license = await getLicense(licenseKey);

        if (!license) {
            return reject(res, "Invalid license key");
        }

        if (String(license.license_type || "").toUpperCase() !== "PC") {
            return reject(res, "This is not a PC license");
        }

        if (normalizeSection(license.license_section) !== requestedSection) {
            return reject(
                res,
                "License belongs to " +
                String(license.license_section || "another") +
                " section, not " + requestedSection
            );
        }

        if (!licenseIsUsable(license)) {
            return reject(res, "License is inactive or expired");
        }

        const { data: devices, error: readError } = await vbSupabase
            .from("license_devices")
            .select("*")
            .eq("license_id", license.id);

        if (readError) throw readError;

        const allDevices = devices || [];

        const existing = allDevices.find(device =>
            String(device.device_id || "") === deviceId &&
            String(device.hardware_fingerprint || "") === fingerprint
        );

        const now = new Date().toISOString();

        // Existing active PC
        if (existing && existing.is_active === true) {
            const { error: updateError } = await vbSupabase
                .from("license_devices")
                .update({ last_check: now })
                .eq("id", existing.id);

            if (updateError) throw updateError;

            return res.json({
                success: true,
                valid: true,
                activated: true,
                message: "PC license verified",
                customer_name: license.customer_name,
                expiry_date: license.expiry_date,
                license_section: license.license_section
            });
        }

        // Previously deactivated PC cannot reactivate automatically
        if (existing) {
            return reject(
                res,
                "This PC was deactivated. Contact License Manager."
            );
        }

        const maxDevices = getMaxDevices(license);

        const activeDevices = allDevices.filter(
            device => device.is_active === true
        );

        if (activeDevices.length >= maxDevices) {
            return res.status(409).json({
                success: false,
                valid: false,
                code: "DEVICE_LIMIT_REACHED",
                message: "Maximum PC activation limit reached (" +
                    activeDevices.length + "/" + maxDevices + ")",
                active_devices: activeDevices.length,
                max_devices: maxDevices
            });
        }

        // First time activation
        const { error: insertError } = await vbSupabase
            .from("license_devices")
            .insert({
                license_id: license.id,
                device_id: deviceId,
                device_name: deviceId,
                motherboard_id: "",
                hardware_fingerprint: fingerprint,
                is_active: true,
                activated_at: now,
                last_check: now
            });

        if (insertError) throw insertError;

        return res.json({
            success: true,
            valid: true,
            activated: true,
            message: "PC license activated successfully",
            customer_name: license.customer_name,
            expiry_date: license.expiry_date,
            license_section: license.license_section
        });

    } catch (error) {
        console.error("[PC CHECK ERROR]", error);

        return res.status(500).json({
            success: false,
            valid: false,
            message: error.message || "PC license verification failed"
        });
    }
});

// ==================================================
// PC LICENSE DEACTIVATION
// ==================================================

app.post("/deactivate", async (req, res) => {
    try {
        const licenseKey = normalize(req.body.license_key).toUpperCase();
        const deviceId = normalize(req.body.device_id);
        const fingerprint = normalize(req.body.hardware_fingerprint);
        const requestedSection = normalizeSection(req.body.license_section);

        if (!licenseKey || !deviceId || !fingerprint || !requestedSection) {
            return reject(res, "Required information is missing", 400);
        }

        const license = await getLicense(licenseKey);

        if (!license) {
            return reject(res, "Invalid license key");
        }

        if (String(license.license_type || "").toUpperCase() !== "PC") {
            return reject(res, "This is not a PC license");
        }

        if (normalizeSection(license.license_section) !== requestedSection) {
            return reject(res, "License section mismatch");
        }

        const { data: device, error: readError } = await vbSupabase
            .from("license_devices")
            .select("*")
            .eq("license_id", license.id)
            .eq("device_id", deviceId)
            .eq("hardware_fingerprint", fingerprint)
            .eq("is_active", true)
            .maybeSingle();

        if (readError) throw readError;

        if (!device) {
            return reject(res, "Active PC binding not found");
        }

        const { error: updateError } = await vbSupabase
            .from("license_devices")
            .update({ is_active: false })
            .eq("id", device.id);

        if (updateError) throw updateError;

        return res.json({
            success: true,
            valid: false,
            message: "PC license deactivated successfully",
            license_section: license.license_section
        });

    } catch (error) {
        console.error("[PC DEACTIVATE ERROR]", error);

        return res.status(500).json({
            success: false,
            valid: false,
            message: error.message || "PC deactivation failed"
        });
    }
});

// ==================================================
// PENDRIVE LICENSE ACTIVATION
// ==================================================

app.post("/api/vbnet/usb/activate", async (req, res) => {
    try {
        const licenseKey = normalize(req.body.license_key).toUpperCase();
        const physicalId = normalizeUsbId(req.body.usb_physical_id);
        const usbName = normalize(req.body.usb_name || "Pendrive").slice(0, 150);
        const requestedSection = normalizeSection(req.body.license_section);

        if (!licenseKey || physicalId.length < 4) {
            return reject(
                res,
                "License key and USB physical ID required",
                400
            );
        }

        if (!requestedSection) {
            return reject(res, "Invalid software section", 400);
        }

        const license = await getLicense(licenseKey);

        if (!license) {
            return reject(res, "Invalid license key");
        }

        if (String(license.license_type || "").toUpperCase() !== "USB") {
            return reject(res, "This is not a pendrive license");
        }

        if (normalizeSection(license.license_section) !== requestedSection) {
            return reject(res, "License section mismatch");
        }

        if (!licenseIsUsable(license)) {
            return reject(res, "License is inactive or expired");
        }

        const hash = usbHash(physicalId);

        const { data: existing, error: readError } = await vbSupabase
            .from("usb_license_devices")
            .select("*")
            .eq("license_id", license.id);

        if (readError) throw readError;

        const bindings = existing || [];
        const samePendrive = bindings.find(x => x.usb_hash === hash);
        const now = new Date().toISOString();

        if (samePendrive && samePendrive.is_active === true) {
            const { error: updateError } = await vbSupabase
                .from("usb_license_devices")
                .update({
                    last_check: now,
                    usb_name: usbName
                })
                .eq("id", samePendrive.id);

            if (updateError) throw updateError;

            return res.json({
                success: true,
                valid: true,
                activated: true,
                message: "Pendrive already activated",
                license_section: license.license_section,
                expiry_date: license.expiry_date
            });
        }

        const maxDevices = getMaxDevices(license);

        const activeBindings = bindings.filter(
            x => x.is_active === true
        );

        if (activeBindings.length >= maxDevices) {
            return res.status(409).json({
                success: false,
                valid: false,
                code: "USB_DEVICE_LIMIT_REACHED",
                message: "Maximum pendrive limit reached (" +
                    activeBindings.length + "/" + maxDevices + ")",
                active_devices: activeBindings.length,
                max_devices: maxDevices
            });
        }

        if (activeBindings.length === 0 &&
            license.usb_rebind_allowed !== true) {
            return reject(
                res,
                "Pendrive activation is locked. Allow New Pendrive in License Manager first.",
                403,
                "USB_REBIND_LOCKED"
            );
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

        if (samePendrive) {
            const { error: updateError } = await vbSupabase
                .from("usb_license_devices")
                .update(bindingData)
                .eq("id", samePendrive.id);

            if (updateError) throw updateError;
        } else {
            const { error: insertError } = await vbSupabase
                .from("usb_license_devices")
                .insert(bindingData);

            if (insertError) throw insertError;
        }

        if (license.usb_rebind_allowed === true) {
            const { error: lockError } = await vbSupabase
                .from("licenses")
                .update({ usb_rebind_allowed: false })
                .eq("id", license.id);

            if (lockError) throw lockError;
        }

        return res.json({
            success: true,
            valid: true,
            activated: true,
            message: "Pendrive activated successfully",
            license_section: license.license_section,
            expiry_date: license.expiry_date,
            active_devices: activeBindings.length + 1,
            max_devices: maxDevices
        });

    } catch (error) {
        console.error("[USB ACTIVATE ERROR]", error);

        return res.status(500).json({
            success: false,
            valid: false,
            message: error.message || "Pendrive activation failed"
        });
    }
});

// ==================================================
// PENDRIVE LICENSE VERIFICATION
// ==================================================

app.post("/api/vbnet/usb/verify", async (req, res) => {
    try {
        const licenseKey = normalize(req.body.license_key).toUpperCase();
        const physicalId = normalizeUsbId(req.body.usb_physical_id);
        const requestedSection = normalizeSection(req.body.license_section);

        if (!licenseKey || physicalId.length < 4) {
            return reject(
                res,
                "License key and USB physical ID required",
                400
            );
        }

        if (!requestedSection) {
            return reject(res, "Invalid software section", 400);
        }

        const license = await getLicense(licenseKey);

        if (!license) {
            return reject(res, "Invalid pendrive license");
        }

        if (String(license.license_type || "").toUpperCase() !== "USB") {
            return reject(res, "This is not a pendrive license");
        }

        if (normalizeSection(license.license_section) !== requestedSection) {
            return reject(res, "License section mismatch");
        }

        if (!licenseIsUsable(license)) {
            return reject(res, "License is inactive or expired");
        }

        const hash = usbHash(physicalId);

        const { data: binding, error: readError } = await vbSupabase
            .from("usb_license_devices")
            .select("*")
            .eq("license_id", license.id)
            .eq("usb_hash", hash)
            .eq("is_active", true)
            .maybeSingle();

        if (readError) throw readError;

        if (!binding) {
            return reject(res, "Authorized pendrive not found");
        }

        const { error: updateError } = await vbSupabase
            .from("usb_license_devices")
            .update({ last_check: new Date().toISOString() })
            .eq("id", binding.id);

        if (updateError) throw updateError;

        return res.json({
            success: true,
            valid: true,
            customer_name: license.customer_name,
            expiry_date: license.expiry_date,
            license_section: license.license_section
        });

    } catch (error) {
        console.error("[USB VERIFY ERROR]", error);

        return res.status(500).json({
            success: false,
            valid: false,
            message: error.message || "Pendrive verification failed"
        });
    }
});

// --------------------------------------------------
// START SERVER
// --------------------------------------------------

app.listen(PORT, "0.0.0.0", () => {
    console.log("VB.NET License API running on port " + PORT);
});
