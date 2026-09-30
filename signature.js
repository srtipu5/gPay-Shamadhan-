const crypto = require('crypto')

// Port of MakeSignature.GenerateSignature (C# reference implementation).
//
//   1. drop `signature` and every blank value
//   2. sort the remaining keys ascending (ordinal)
//   3. stringA  = k1=v1&k2=v2&...
//   4. signTemp = AppKey + "&" + stringA + "&" + AppKey
//   5. signature = Base64( SHA256(signTemp, UTF-8) )

const SIGNATURE = 'signature'

const isBlank = (v) => v === undefined || v === null || String(v).trim() === ''

// C# sorts with StringComparer.Ordinal, i.e. by UTF-16 code unit, not by locale.
const ordinal = (a, b) => (a < b ? -1 : a > b ? 1 : 0)

const buildStringA = (params) =>
    Object.keys(params)
        .filter((k) => k !== SIGNATURE && !isBlank(params[k]))
        .sort(ordinal)
        .map((k) => `${k}=${params[k]}`)
        .join('&')

const generateSignature = (params, appKey) => {
    if (!appKey) throw new Error('AppKey is missing (set PG_APP_KEY in .env)')

    const signTemp = `${appKey}&${buildStringA(params)}&${appKey}`
    return crypto.createHash('sha256').update(signTemp, 'utf8').digest('base64')
}

// Returns a copy of `params` carrying its own signature -- use on outgoing requests.
const withSignature = (params, appKey) => ({
    ...params,
    signature: generateSignature(params, appKey),
})

// Use on the notify callback and on responses coming back from the platform.
const verify = (params, appKey) => {
    if (!params || isBlank(params[SIGNATURE])) return false

    // Sign `params`, not the signature field itself -- generateSignature rebuilds
    // stringA from the payload and compares it against what arrived.
    const expected = Buffer.from(generateSignature(params, appKey))
    const actual = Buffer.from(String(params[SIGNATURE]))
    return expected.length === actual.length && crypto.timingSafeEqual(expected, actual)
}

module.exports = { buildStringA, generateSignature, withSignature, verify }
