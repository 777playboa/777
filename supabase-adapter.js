'use strict';

/**
 * 777 Auth — Supabase PostgreSQL Database Adapter.
 * Connects 777 Auth Server with Supabase for persistent licenses and HWID bindings.
 */

let createClient = null;
try {
    createClient = require('@supabase/supabase-js').createClient;
} catch (e) {
    // optional package
}

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_KEY;
const tableName = process.env.SUPABASE_TABLE || 'client777_licenses';

let client = null;

if (createClient && supabaseUrl && supabaseKey) {
    try {
        client = createClient(supabaseUrl, supabaseKey, {
            auth: { persistSession: false }
        });
        console.log(`[777 Auth] Supabase client initialized: ${supabaseUrl} (table: ${tableName})`);
    } catch (err) {
        console.error('[777 Auth] Failed to initialize Supabase client:', err.message);
    }
} else {
    console.log('[777 Auth] Supabase not configured or env vars missing; running with local licenses.json fallback.');
}

async function loadLicensesFromSupabase() {
    if (!client) return null;
    try {
        const { data, error } = await client.from(tableName).select('*');
        if (error) {
            console.error('[777 Auth] Supabase select error:', error.message);
            return null;
        }
        const map = new Map();
        if (Array.isArray(data)) {
            for (const row of data) {
                const cleanKey = (row.license_key || '').replace(/[^A-Za-z0-9]/g, '').toUpperCase();
                map.set(cleanKey, {
                    hwid: row.hwid || null,
                    type: row.type || 'lifetime_premium',
                    active: row.active !== false,
                    discordId: row.discord_id || null,
                    notes: row.notes || '',
                    expiresAt: row.expires_at || null
                });
            }
        }
        console.log(`[777 Auth] Successfully synced ${map.size} licenses from Supabase (${tableName})`);
        return map;
    } catch (e) {
        console.error('[777 Auth] Error querying Supabase:', e.message);
        return null;
    }
}

async function fetchSingleLicense(licenseKey, retries = 2) {
    if (!client || !licenseKey) return null;
    const raw = String(licenseKey).trim();
    const cleanKey = raw.replace(/[^A-Za-z0-9]/g, '').toUpperCase();
    const formattedKey = cleanKey.length === 20
        ? `${cleanKey.slice(0, 4)}-${cleanKey.slice(4, 8)}-${cleanKey.slice(8, 12)}-${cleanKey.slice(12, 16)}-${cleanKey.slice(16, 20)}`
        : cleanKey;
    for (let attempt = 0; attempt <= retries; attempt++) {
        try {
            const { data, error } = await client
                .from(tableName)
                .select('*')
                .or(`license_key.eq.${raw},license_key.eq.${cleanKey},license_key.eq.${formattedKey},license_key.ilike.${cleanKey},license_key.ilike.${formattedKey}`)
                .limit(1);
            if (error) {
                console.error(`[777 Auth] Supabase fetchSingleLicense error (attempt ${attempt + 1}):`, error.message);
                if (attempt < retries) {
                    await new Promise(r => setTimeout(r, 600));
                    continue;
                }
                return null;
            }
            if (!data || data.length === 0) return null;
            const row = data[0];
            return {
                hwid: row.hwid || null,
                type: row.type || 'lifetime_premium',
                active: row.active !== false,
                discordId: row.discord_id || null,
                notes: row.notes || '',
                expiresAt: row.expires_at || null
            };
        } catch (e) {
            console.error(`[777 Auth] fetchSingleLicense error (attempt ${attempt + 1}):`, e.message);
            if (attempt < retries) {
                await new Promise(r => setTimeout(r, 600));
                continue;
            }
            return null;
        }
    }
    return null;
}

async function saveLicenseToSupabase(key, record) {
    if (!client) return false;
    try {
        const { error } = await client.from(tableName).upsert({
            license_key: key,
            hwid: record.hwid || null,
            type: record.type || 'lifetime_premium',
            active: record.active !== false,
            discord_id: record.discordId || null,
            notes: record.notes || '',
            expires_at: record.expiresAt || null,
            updated_at: new Date().toISOString()
        });
        if (error) {
            console.error(`[777 Auth] Failed to upsert license ${key} to Supabase:`, error.message);
            return false;
        }
        return true;
    } catch (e) {
        console.error(`[777 Auth] Error saving license ${key} to Supabase:`, e.message);
        return false;
    }
}

async function syncAllToSupabase(licensesMap) {
    if (!client || !licensesMap) return false;
    try {
        const rows = [];
        for (const [key, record] of licensesMap.entries()) {
            rows.push({
                license_key: key,
                hwid: record.hwid || null,
                type: record.type || 'lifetime_premium',
                active: record.active !== false,
                discord_id: record.discordId || null,
                notes: record.notes || '',
                expires_at: record.expiresAt || null,
                updated_at: new Date().toISOString()
            });
        }
        if (rows.length === 0) return true;
        const { error } = await client.from(tableName).upsert(rows);
        if (error) {
            console.error('[777 Auth] Error batch upserting to Supabase:', error.message);
            return false;
        }
        console.log(`[777 Auth] Batch synced ${rows.length} licenses to Supabase`);
        return true;
    } catch (e) {
        console.error('[777 Auth] Error during batch sync to Supabase:', e.message);
        return false;
    }
}

module.exports = {
    isConfigured: () => client !== null,
    loadLicensesFromSupabase,
    fetchSingleLicense,
    saveLicenseToSupabase,
    syncAllToSupabase
};
