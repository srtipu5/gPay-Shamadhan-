#!/usr/bin/env node
//
// Finds the signing rule the platform used for a payload it sent us.
//
//   node diagnose-signature.js "/notify?orderDate=...&signature=..."
//   node diagnose-signature.js --deep "/notify?..."   (also tries transformed
//        AppKeys and hash-then-AES rules; slower)
//   node diagnose-signature.js notification.json
//   echo '{"orderNo":"...","signature":"..."}' | node diagnose-signature.js
//
// Reads PG_APP_KEY (and PG_APP_ID / PG_MERCHANT_ID / PG_COUNTER_NO) from .env, or
// takes the AppKey as the 2nd argument. Everything runs locally.

const fs = require('fs')
const path = require('path')
const { findRule, parseCallback } = require('./signature-finder')

const env = {}
const envFile = path.join(__dirname, '.env')
if (fs.existsSync(envFile)) {
    for (const line of fs.readFileSync(envFile, 'utf8').split('\n')) {
        const m = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
        if (m) env[m[1]] = m[2].trim().replace(/^(['"])(.*)\1$/, '$2')
    }
}
const setting = (name) => process.env[name] || env[name] || ''

const args = process.argv.slice(2).filter((a) => a !== '--deep')
const deep = process.argv.includes('--deep')

const arg = args[0]
const raw = arg ? (fs.existsSync(arg) ? fs.readFileSync(arg, 'utf8') : arg) : fs.readFileSync(0, 'utf8')
const payload = parseCallback(raw)
const appKey = args[1] || setting('PG_APP_KEY')

if (!payload.signature) throw new Error('payload has no `signature` field to match against')
if (!appKey) throw new Error('no AppKey -- set PG_APP_KEY in .env or pass it as the 2nd argument')

const decoded = Buffer.from(payload.signature, 'base64')
console.log(`payload fields : ${Object.keys(payload).filter((k) => k !== 'signature').join(', ')}`)
console.log(`signature      : ${payload.signature}  (${decoded.length} bytes decoded)`)
console.log(`AppKey         : ${appKey.length} chars, "${appKey.slice(0, 2)}…${appKey.slice(-2)}"`)

const { matches, tried } = findRule(payload, appKey, {
    appId: setting('PG_APP_ID'),
    merchantId: setting('PG_MERCHANT_ID'),
    counterNo: setting('PG_COUNTER_NO'),
    version: '1.0',
    signType: 'SHA256',
}, {
    deep,
    onProgress: ({ extras, baseKeys, keyVariant }) => {
        if (keyVariant) return console.log(`  trying AppKey as: ${keyVariant}`)
        console.log(`\nNo match on the payload as sent. Now trying ${2 ** extras.length} combinations of`)
        console.log(`unsent fields (${extras.join(', ')}) x ${2 ** baseKeys.length} subsets of the sent fields...`)
        if (deep) console.log('then --deep: transformed AppKeys and hash-then-encrypt rules...')
    },
})

console.log(`combinations   : ${tried.toLocaleString()}\n`)

if (!matches.length) {
    console.log('No match. Things to check next:')
    console.log('  - is this the same AppKey the notification was signed with? Some')
    console.log('    platforms issue a separate notify/callback key.')
    console.log('  - does the spec list a notify field the callback did not send')
    console.log('    (a nonce, a sequence number, the counterNo)?')
    console.log('  - does it sign the raw query string in the order sent, including')
    console.log('    percent-encoding, rather than decoded key=value pairs?')
    if (!deep) console.log('\nRe-run with --deep to also try transformed AppKeys and hash-then-AES rules.')
    process.exit(1)
}

console.log(`MATCH (${matches.length} distinct):\n`)
for (const m of matches) {
    console.log(`  algorithm   : ${m.rule}`)
    console.log(`  key order   : ${m.keys}`)
    console.log(`  sign source : ${m.format}`)
    if (m.note) console.log(`  fields      : ${m.note}`)
    console.log(`                ${m.source}\n`)
}
