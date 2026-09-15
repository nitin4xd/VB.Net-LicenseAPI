require('dotenv').config();

const express = require('express');
const { createClient } = require('@supabase/supabase-js');

const app = express();

app.use(express.json());

const supabase = createClient(
    process.env.SUPABASE_URL,
    process.env.SUPABASE_SECRET_KEY
);

// Home
app.get('/', (req, res) => {
    res.send('License API is working!');
});

// Activate License
app.post('/activate', async (req, res) => {

    try {

        const { license_key, device_id, device_name } = req.body;

        if (!license_key || !device_id) {
            return res.status(400).json({
                success: false,
                message: 'License key and device ID are required'
            });
        }

        // Find license
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('*')
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
            .select('*')
            .eq('license_id', license.id)
            .eq('device_id', device_id)
            .maybeSingle();

        if (existingDevice) {

            await supabase
                .from('license_devices')
                .update({
                    is_active: true,
                    last_check: new Date().toISOString()
                })
                .eq('id', existingDevice.id);

            return res.json({
                success: true,
                message: 'License already activated on this computer'
            });
        }

        // Count active devices
        const { data: devices } = await supabase
            .from('license_devices')
            .select('id')
            .eq('license_id', license.id)
            .eq('is_active', true);

        const deviceCount = devices ? devices.length : 0;

        if (deviceCount >= license.max_devices) {
            return res.status(403).json({
                success: false,
                message: 'Maximum device limit reached'
            });
        }

        // Activate new device
        const { error: insertError } = await supabase
            .from('license_devices')
            .insert({
                license_id: license.id,
                device_id: device_id,
                device_name: device_name || null,
                activated_at: new Date().toISOString(),
                last_check: new Date().toISOString(),
                is_active: true
            });

        if (insertError) {
            return res.status(500).json({
                success: false,
                message: insertError.message
            });
        }

        // Update license activation date
        await supabase
            .from('licenses')
            .update({
                activation_date: new Date().toISOString(),
                last_check: new Date().toISOString()
            })
            .eq('id', license.id);

        res.json({
            success: true,
            message: 'License activated successfully',
            expiry_date: license.expiry_date
        });

    } catch (err) {

        res.status(500).json({
            success: false,
            message: err.message
        });

    }
});


// Check License
app.post('/check', async (req, res) => {

    try {

        const { license_key, device_id } = req.body;

        if (!license_key || !device_id) {
            return res.status(400).json({
                success: false,
                valid: false,
                message: 'License key and device ID are required'
            });
        }

        // Find license
        const { data: license, error: licenseError } = await supabase
            .from('licenses')
            .select('*')
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
            .select('*')
            .eq('license_id', license.id)
            .eq('device_id', device_id)
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

        return res.status(500).json({
            success: false,
            valid: false,
            message: err.message
        });

    }
});


// Deactivate License Device
app.post('/deactivate', async (req, res) => {

    try {

        const { license_key, device_id } = req.body;

        if (!license_key || !device_id) {
            return res.status(400).json({
                success: false,
                message: 'License key and device ID are required'
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
            .eq('is_active', true)
            .maybeSingle();

        if (deviceError) {
            return res.status(500).json({
                success: false,
                message: deviceError.message
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
            return res.status(500).json({
                success: false,
                message: updateError.message
            });
        }

        return res.json({
            success: true,
            message: 'License deactivated successfully'
        });

    } catch (err) {

        return res.status(500).json({
            success: false,
            message: err.message
        });

    }
});


const PORT = process.env.PORT || 3000;

app.listen(PORT, '0.0.0.0', () => {
    console.log(`License API running on port ${PORT}`);
});
