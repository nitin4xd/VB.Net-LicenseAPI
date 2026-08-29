const http = require('http');

const data = JSON.stringify({
    license_key: 'LP-TEST-2026-0001',
    device_id: 'TEST-PC-001',
    device_name: 'Test Computer'
});

const options = {
    hostname: 'localhost',
    port: 3000,
    path: '/activate',
    method: 'POST',
    headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
    }
};

const req = http.request(options, (res) => {

    let body = '';

    res.on('data', (chunk) => {
        body += chunk;
    });

    res.on('end', () => {
        console.log('Status:', res.statusCode);
        console.log('Response:', body);
    });

});

req.on('error', (error) => {
    console.error('Error:', error.message);
});

req.write(data);
req.end();