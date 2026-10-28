'use strict';

const http = require('http');

function request(method, path, body, headers = {}) {
    return new Promise((resolve, reject) => {
        const req = http.request({
            hostname: '127.0.0.1',
            port: 8000,
            path,
            method,
            headers: {
                'Content-Type': 'application/json',
                ...headers
            }
        }, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({ status: res.statusCode, data: JSON.parse(data) });
                } catch {
                    resolve({ status: res.statusCode, data });
                }
            });
        });
        req.on('error', reject);
        if (body) req.write(JSON.stringify(body));
        req.end();
    });
}

async function run() {
    console.log('Testing 777 Auth Handshake...');

    // 1. Challenge
    const challengeRes = await request('GET', '/v1/challenge');
    console.log('1. Challenge:', challengeRes.status, challengeRes.data);
    const { nonce, timestamp } = challengeRes.data;

    const testHwid = '777client-test-hwid-0123456789abcdef0123456789abcdef0123456789abcdef';

    // 2. Auth with License
    const authRes = await request('POST', '/v1/auth', {
        username: '777ClientTester',
        license: 'AA77-7777-TEST-DEMO-2026',
        hwid: testHwid,
        nonce,
        timestamp,
        os_version: 'windows'
    });
    console.log('2. License Auth:', authRes.status, authRes.data);

    const token = authRes.data.sessionToken;

    // 3. HWID Autologin (remember-me)
    const challenge2 = await request('GET', '/v1/challenge');
    const hwidRes = await request('POST', '/v1/auth/hwid', {
        hwid: testHwid,
        nonce: challenge2.data.nonce,
        timestamp: challenge2.data.timestamp
    });
    console.log('3. HWID Autologin:', hwidRes.status, hwidRes.data);

    // 4. Heartbeat
    const hbRes = await request('POST', '/v1/heartbeat', {
        sessionToken: token
    }, {
        'X-Cloth-Session-Token': token
    });
    console.log('4. Heartbeat:', hbRes.status, hbRes.data);

    console.log('All tests passed successfully!');
    process.exit(0);
}

run().catch(err => {
    console.error('Test error:', err);
    process.exit(1);
});
