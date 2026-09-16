require('dotenv').config();

const express = require('express');
const rateLimit = require('express-rate-limit');
const { createClient } = require('@supabase/supabase-js');
const helmet = require('helmet');
const cors = require('cors');

const app = express();

app.use(helmet());

app.use(cors({
    origin: false
}));

app.use(express.json({ limit: '10kb' }));

function isValidLicenseInput(value, maxLength) {
    return typeof value === 'string' &&
           value.trim().length > 0 &&
           value.length <= maxLength;
}

// Security: Rate Limiting
const activateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    message: {
        success: false,
        message: 'Too many activation attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
});


const deactivateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: {
        success: false,
        message: 'Too many deactivation attempts. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
});


const checkLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 60,
    message: {
        success: false,
        valid: false,
        message: 'Too many license checks. Please try again later.'
    },
    standardHeaders: true,
    legacyHeaders: false
});


if (!process.env.SUPABASE_URL || !process.env.SUPABASE_SECRET_KEY) {
    console.error('Missing Supabase environment variables');
    process.exit(1);
}


const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);

// Home
app.get('/', (req, res) => {
    res.send('License API is working!');
});


// Activate License
app.post('/activate', activateLimiter, async (req, res) => {

    try {

        const { license_key, device_id, device_name, hardware_fingerprint } = req.body;

        if (
            !isValidLicenseInput(license_key, 100) ||
            !isValidLicenseInput(device_id, 200) ||
            !isValidLicenseInput(hardware_fingerprint, 128)
        ) {
            return res.status(400).json({
                success: false,
                message: 'Invalid license request data'
            });
        }

        // Find license
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('id, license_key, status, expiry_date, max_devices, customer_name')
            .eq('license_key', license_key)
            .single();

        if (licenseError || !license) {
            return res.status(404).json({
                success: false,
                message: 'Invalid license key'
            });
        }

        // Check status
        if (license.status !== 'ACTIVE') {
            return res.status(403).json({
                success: false,
                message: 'License is ' + license.status
            });
        }

        // Check expiry
        if (license.expiry_date) {

            const today = new Date();
            const expiry = new Date(license.expiry_date);

            if (today > expiry) {

                await supabase
                    .from('licenses')
                    .update({ status: 'EXPIRED' })
                    .eq('id', license.id);

                return res.status(403).json({
                    success: false,
                    message: 'License has expired'
                });
            }
        }

// Check existing device
const { data: existingDevice } = await supabase
    .from('license_devices')
    .select('id, is_active, hardware_fingerprint')
    .eq('license_id', license.id)
    .eq('device_id', device_id)
    .maybeSingle();

if (existingDevice) {

    // Device already active
    if (existingDevice.is_active === true) {

        // Hardware fingerprint must match
        if (existingDevice.hardware_fingerprint !== hardware_fingerprint) {
            return res.status(403).json({
                success: false,
                message: 'This license is already bound to another hardware configuration'
            });
        }

        // Do NOT overwrite hardware fingerprint
        await supabase
            .from('license_devices')
            .update({
                last_check: new Date().toISOString()
            })
            .eq('id', existingDevice.id);

        return res.json({
            success: true,
            message: 'License already activated on this computer'
        });
    }

    // Previously deactivated device
    if (existingDevice.hardware_fingerprint !== hardware_fingerprint) {
        return res.status(403).json({
            success: false,
            message: 'Hardware does not match the original activated computer'
        });
    }

    const { error: reactivateError } = await supabase
    .from('license_devices')
    .update({
        is_active: true,
        last_check: new Date().toISOString()
    })
    .eq('id', existingDevice.id);

if (reactivateError) {
    console.error('DEVICE REACTIVATION ERROR:', reactivateError);

    if (reactivateError.message &&
        reactivateError.message.includes('MAX_DEVICES_REACHED')) {
        return res.status(403).json({
            success: false,
            message: 'Maximum device limit reached'
        });
    }

    return res.status(500).json({
        success: false,
        message: 'Unable to reactivate license'
    });
}

return res.json({
    success: true,
    message: 'License reactivated successfully'
});
}
    // Check device limit
const { count: activeDeviceCount, error: countError } = await supabase
    .from('license_devices')
    .select('*', { count: 'exact', head: true })
    .eq('license_id', license.id);

if (countError) {
    console.error('DEVICE COUNT ERROR:', countError);

    return res.status(500).json({
        success: false,
        message: 'Unable to verify device limit'
    });
}

if (activeDeviceCount >= license.max_devices) {
    return res.status(403).json({
        success: false,
        message: 'Maximum device limit reached'
    });
}


// Add new device
const { error: insertError } = await supabase
    .from('license_devices')
    .insert([{
        license_id: license.id,
        device_id: device_id,
        device_name: device_name || 'Unknown Device',
        hardware_fingerprint: hardware_fingerprint,
        is_active: true,
        last_check: new Date().toISOString()
    }]);

if (insertError) {

    console.error('DEVICE INSERT ERROR:', insertError);

    // Database trigger: maximum device limit reached
    if (insertError.message &&
        insertError.message.includes('MAX_DEVICES_REACHED')) {

        return res.status(403).json({
            success: false,
            message: 'Maximum device limit reached'
        });
    }

    return res.status(500).json({
        success: false,
        message: 'Unable to activate license'
    });
}

return res.json({
    success: true,
    message: 'License activated successfully'
});
    
    } catch (err) {

    console.error('ACTIVATE ERROR:', err);

    return res.status(500).json({
        success: false,
        message: 'Server error'
    });

    }
});


// Check License
app.post('/check', checkLimiter, async (req, res) => {

    try {

        const { license_key, device_id, hardware_fingerprint } = req.body;

        if (
            !isValidLicenseInput(license_key, 100) ||
            !isValidLicenseInput(device_id, 200) ||
            !isValidLicenseInput(hardware_fingerprint, 128)
        ) {
            return res.status(400).json({
                success: false,
                valid: false,
                message: 'Invalid license request data'
            });
        }

        // Find license
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('id, license_key, status, expiry_date, customer_name')
            .eq('license_key', license_key)
            .single();

        if (licenseError || !license) {
            return res.status(404).json({
                success: false,
                valid: false,
                message: 'Invalid license key'
            });
        }

        // Check status
        if (license.status !== 'ACTIVE') {
            return res.status(403).json({
                success: false,
                valid: false,
                message: 'License is ' + license.status
            });
        }

        // Check expiry
        if (license.expiry_date) {

            const today = new Date();
            const expiry = new Date(license.expiry_date);

            if (today > expiry) {

                await supabase
                    .from('licenses')
                    .update({ status: 'EXPIRED' })
                    .eq('id', license.id);

                return res.status(403).json({
                    success: false,
                    valid: false,
                    message: 'License has expired'
                });
            }
        }

        // Check device
        const { data: device, error: deviceError } = await supabase
            .from('license_devices')
            .select('id')
            .eq('license_id', license.id)
            .eq('device_id', device_id)
            .eq('hardware_fingerprint', hardware_fingerprint)
            .eq('is_active', true)
            .maybeSingle();

        if (deviceError || !device) {
            return res.status(403).json({
                success: false,
                valid: false,
                message: 'This computer is not activated'
            });
        }

        // Update last check
        await supabase
            .from('license_devices')
            .update({
                last_check: new Date().toISOString()
            })
            .eq('id', device.id);

        await supabase
            .from('licenses')
            .update({
                last_check: new Date().toISOString()
            })
            .eq('id', license.id);

        return res.json({
            success: true,
            valid: true,
            message: 'License is valid',
            customer_name: license.customer_name,
            expiry_date: license.expiry_date
        });

    } catch (err) {
    console.error('CHECK ERROR:', err);
    return res.status(500).json({
        success: false,
        valid: false,
        message: 'Server error'
    });
    }
});


// Deactivate License Device
app.post('/deactivate', deactivateLimiter, async (req, res) => {

    try {

        const { license_key, device_id, hardware_fingerprint } = req.body;

        if (
            !isValidLicenseInput(license_key, 100) ||
            !isValidLicenseInput(device_id, 200) ||
            !isValidLicenseInput(hardware_fingerprint, 128)
        ) {
            return res.status(400).json({
                success: false,
                message: 'Invalid license request data'
            });
        }

        // Find license
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('id, license_key')
            .eq('license_key', license_key)
            .single();

        if (licenseError || !license) {
            return res.status(404).json({
                success: false,
                message: 'Invalid license key'
            });
        }

        // Find active device
        const { data: device, error: deviceError } = await supabase
            .from('license_devices')
            .select('id')
            .eq('license_id', license.id)
            .eq('device_id', device_id)
            .eq('hardware_fingerprint', hardware_fingerprint)
            .eq('is_active', true)
            .maybeSingle();

        if (deviceError) {
            console.error('DEACTIVATE DEVICE ERROR:', deviceError);

            return res.status(500).json({
                success: false,
                message: 'Unable to verify activation'
            });
        }

        if (!device) {
            return res.status(404).json({
                success: false,
                message: 'This computer is not currently activated'
            });
        }

        // Deactivate device
        const { error: updateError } = await supabase
            .from('license_devices')
            .update({
                is_active: false,
                last_check: new Date().toISOString()
            })
            .eq('id', device.id);

        if (updateError) {
            console.error('DEACTIVATE UPDATE ERROR:', updateError);

            return res.status(500).json({
                success: false,
                message: 'Unable to deactivate license'
            });
        }

        return res.json({
            success: true,
            message: 'License deactivated successfully'
        });

    } catch (err) {

    console.error('DEACTIVATE ERROR:', err);

    return res.status(500).json({
        success: false,
        message: 'Server error'
    });
    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`License API running on port ${PORT}`);
});
