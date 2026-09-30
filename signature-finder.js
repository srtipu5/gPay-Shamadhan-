// Searches for the signing rule that produces a signature the platform sent us.
//
// Used by diagnose-signature.js from the command line, and by the /notify handler
// so a failing callback explains itself in the log instead of just being rejected.
//
// Everything here is local: it hashes candidate strings and compares them against
// the signature already in the payload. Nothing is sent anywhere.

const crypto = require('crypto')

const ORDERS = {
    ordinal: (k) => [...k].sort((a, b) => (a < b ? -1 : a > b ? 1 : 0)),
    'ordinal-lowercased': (k) => [...k].sort((a, b) => (a.toLowerCase() < b.toLowerCase() ? -1 : 1)),
    locale: (k) => [...k].sort((a, b) => a.localeCompare(b)),
    'as-received': (k) => k,
    'reverse-ordinal': (k) => [...k].sort((a, b) => (a < b ? 1 : -1)),
}

const JOINS = {
    'k=v&k=v': (keys, p) => keys.map((k) => `${k}=${p[k]}`).join('&'),
    'k=v (no sep)': (keys, p) => keys.map((k) => `${k}=${p[k]}`).join(''),
    'kv (no = or &)': (keys, p) => keys.map((k) => `${k}${p[k]}`).join(''),
    'values only &': (keys, p) => keys.map((k) => p[k]).join('&'),
    'values only': (keys, p) => keys.map((k) => p[k]).join(''),
}

const TEMPLATES = {
    'key&A&key': (a, k) => `${k}&${a}&${k}`,
    'A&key=key': (a, k) => `${a}&key=${k}`,
    'A&key': (a, k) => `${a}&${k}`,
    'A+key': (a, k) => `${a}${k}`,
    'key+A': (a, k) => `${k}${a}`,
    A: (a) => a,
}

const HASHES = {
    sha256: (s) => crypto.createHash('sha256').update(s, 'utf8').digest(),
    sha1: (s) => crypto.createHash('sha1').update(s, 'utf8').digest(),
    md5: (s) => crypto.createHash('md5').update(s, 'utf8').digest(),
    sha512: (s) => crypto.createHash('sha512').update(s, 'utf8').digest(),
    'hmac-sha256': (s, k) => crypto.createHmac('sha256', k).update(s, 'utf8').digest(),
    'hmac-sha1': (s, k) => crypto.createHmac('sha1', k).update(s, 'utf8').digest(),
    'hmac-md5': (s, k) => crypto.createHmac('md5', k).update(s, 'utf8').digest(),
}

const ENCODINGS = {
    base64: (b) => b.toString('base64'),
    hex: (b) => b.toString('hex'),
    HEX: (b) => b.toString('hex').toUpperCase(),
    'base64(hex)': (b) => Buffer.from(b.toString('hex')).toString('base64'),
    'base64(HEX)': (b) => Buffer.from(b.toString('hex').toUpperCase()).toString('base64'),
}

// Spec 3.2 calls the AppKey an AES key, so try encrypting the source too.
const aes = (source, key, mode) => {
    const k = Buffer.from(key, 'utf8')
    if (![16, 24, 32].includes(k.length)) return null
    const c = crypto.createCipheriv(
        `aes-${k.length * 8}-${mode}`, k, mode === 'cbc' ? Buffer.alloc(16, 0) : null
    )
    return Buffer.concat([c.update(source, 'utf8'), c.final()])
}

// The AppKey may not be used as the literal text we were given: some platforms
// HMAC with its decoded bytes, or use a digest of it as the secret.
const keyVariants = (appKey) => {
    const out = [['as text', appKey]]
    const push = (label, value) => {
        if (value && !out.some(([, v]) => v === value)) out.push([label, value])
    }

    push('UPPERCASE', appKey.toUpperCase())
    push('lowercase', appKey.toLowerCase())
    push('md5-hex of AppKey', crypto.createHash('md5').update(appKey).digest('hex'))
    push('sha256-hex of AppKey', crypto.createHash('sha256').update(appKey).digest('hex'))

    if (/^[A-Za-z0-9+/]+={0,2}$/.test(appKey) && appKey.length % 4 === 0) {
        push('base64-decoded', Buffer.from(appKey, 'base64').toString('latin1'))
    }
    if (/^[0-9a-fA-F]+$/.test(appKey) && appKey.length % 2 === 0) {
        push('hex-decoded', Buffer.from(appKey, 'hex').toString('latin1'))
    }
    return out
}

// Two-stage rules: hash the source, then AES-encrypt the digest. A 32-byte
// signature is exactly AES(16-byte MD5) or AES of a 32-char hex digest.
const compositions = (digest, appKey) => {
    const out = []
    for (const mode of ['ecb', 'cbc']) {
        for (const [form, plain] of [
            ['raw', digest],
            ['hex', Buffer.from(digest.toString('hex'))],
            ['base64', Buffer.from(digest.toString('base64'))],
        ]) {
            try {
                const k = Buffer.from(appKey, 'utf8')
                if (![16, 24, 32].includes(k.length)) continue
                const c = crypto.createCipheriv(
                    `aes-${k.length * 8}-${mode}`, k, mode === 'cbc' ? Buffer.alloc(16, 0) : null
                )
                out.push([`then aes-${mode} of ${form} digest`, Buffer.concat([c.update(plain), c.final()])])
            } catch {
                /* key length rejected -- skip */
            }
        }
    }
    return out
}

const subsets = (list) => list.reduce((acc, item) => acc.concat(acc.map((s) => [...s, item])), [[]])

const search = (fields, expected, appKey, { orders = ORDERS, dropBlankOnly = false, note = '', counter } = {}) => {
    const found = []
    const allKeys = Object.keys(fields).filter((k) => k !== 'signature')

    for (const dropBlank of dropBlankOnly ? [true] : [true, false]) {
        const keys = dropBlank
            ? allKeys.filter((k) => fields[k] !== null && String(fields[k]).trim() !== '')
            : allKeys

        for (const [orderName, order] of Object.entries(orders)) {
            const ordered = order(keys)

            for (const [joinName, join] of Object.entries(JOINS)) {
                const stringA = join(ordered, fields)

                for (const [tplName, tpl] of Object.entries(TEMPLATES)) {
                    const source = tpl(stringA, appKey)
                    const outputs = Object.entries(HASHES).map(([n, h]) => [n, h(source, appKey)])
                    for (const mode of ['ecb', 'cbc']) {
                        const out = aes(source, appKey, mode)
                        if (out) outputs.push([`aes-${mode}`, out])
                    }

                    for (const [algName, digest] of outputs) {
                        for (const [encName, encode] of Object.entries(ENCODINGS)) {
                            if (counter) counter.tried++
                            if (encode(digest) === expected) {
                                found.push({
                                    rule: `${algName} / ${encName}`,
                                    keys: `${orderName}, blank values ${dropBlank ? 'dropped' : 'kept'}`,
                                    format: `${joinName} wrapped as ${tplName}`,
                                    note,
                                    source: source.split(appKey).join('<AppKey>'),
                                })
                            }
                        }
                    }
                }
            }
        }
    }
    return found
}

// `known` holds values the platform may sign without sending back (appId,
// merchantId, ...). Pass 1 tries the payload as received; pass 2 tries every
// combination of injected known fields against every subset of the sent fields.
const findRule = (payload, appKey, known = {}, { onProgress, deep = false } = {}) => {
    const expected = payload.signature
    if (!expected) throw new Error('payload has no `signature` field to match against')
    if (!appKey) throw new Error('no AppKey supplied')

    const counter = { tried: 0 }
    const baseKeys = Object.keys(payload).filter((k) => k !== 'signature')

    let matches = search(payload, expected, appKey, { counter })

    if (!matches.length) {
        const extras = Object.entries(known).filter(([, v]) => v)
        if (onProgress) onProgress({ extras: extras.map(([k]) => k), baseKeys })

        for (const extra of subsets(extras)) {
            for (const subset of subsets(baseKeys)) {
                if (subset.length < 2) continue

                const fields = {}
                for (const k of subset) fields[k] = payload[k]
                for (const [k, v] of extra) fields[k] = v

                const dropped = baseKeys.filter((k) => !subset.includes(k))
                const note = [
                    extra.length ? `+ unsent: ${extra.map(([k]) => k).join(', ')}` : '',
                    dropped.length ? `- excluded: ${dropped.join(', ')}` : '',
                ].filter(Boolean).join('  ')

                matches = matches.concat(
                    search(fields, expected, appKey, {
                        orders: { ordinal: ORDERS.ordinal }, dropBlankOnly: true, note, counter,
                    })
                )
            }
        }
    }

    // Pass 3 (CLI only -- it is slow) -- the AppKey may be transformed before use,
    // and the digest may be encrypted afterwards.
    if (!matches.length && deep) {
        for (const [keyLabel, variant] of keyVariants(appKey)) {
            if (onProgress) onProgress({ keyVariant: keyLabel })

            const found = search(payload, expected, variant, {
                counter,
                note: keyLabel === 'as text' ? '' : `AppKey used as: ${keyLabel}`,
            })
            matches = matches.concat(found)

            for (const [, v] of Object.entries(HASHES)) {
                for (const [joinName, join] of Object.entries(JOINS)) {
                    const keys = ORDERS.ordinal(baseKeys.filter((k) => String(payload[k]).trim() !== ''))
                    const stringA = join(keys, payload)

                    for (const [tplName, tpl] of Object.entries(TEMPLATES)) {
                        const source = tpl(stringA, variant)
                        for (const [compLabel, out] of compositions(v(source, variant), appKey)) {
                            for (const [encName, encode] of Object.entries(ENCODINGS)) {
                                counter.tried++
                                if (encode(out) === expected) {
                                    matches.push({
                                        rule: `${compLabel} / ${encName}`,
                                        keys: 'ordinal, blank values dropped',
                                        format: `${joinName} wrapped as ${tplName}`,
                                        note: `AppKey used as: ${keyLabel}`,
                                        source: source.split(variant).join('<AppKey>'),
                                    })
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Identical sign sources can match under several equivalent orderings.
    const unique = [...new Map(matches.map((m) => [`${m.rule}|${m.source}`, m])).values()]
    return { matches: unique, tried: counter.tried }
}

// A query string is NOT form-urlencoded here: '+' is part of base64, not a space.
const parseCallback = (text) => {
    const trimmed = String(text).trim()
    if (trimmed.startsWith('{')) return JSON.parse(trimmed)

    const qs = trimmed.includes('?') ? trimmed.slice(trimmed.indexOf('?') + 1) : trimmed
    const out = {}
    for (const pair of qs.split('&')) {
        if (!pair) continue
        const eq = pair.indexOf('=')
        const key = eq === -1 ? pair : pair.slice(0, eq)
        const value = eq === -1 ? '' : pair.slice(eq + 1)
        try {
            out[decodeURIComponent(key)] = decodeURIComponent(value)
        } catch {
            out[key] = value // malformed %-escape: keep it verbatim
        }
    }
    return out
}

module.exports = { findRule, parseCallback }
