const crypto = require('crypto')

// Port of MakeEnc (C# reference implementation): AES-CBC / PKCS7 with a random
// per-message IV, transmitted as Base64( IV || ciphertext ).
//
// Spec 3.2: the AppKey doubles as the AES key for sensitive fields.

const AES_BLOCK_SIZE = 16 // 16 bytes = 128 bits

// C# does Encoding.UTF8.GetBytes(key), so the AppKey text itself must be
// 16 / 24 / 32 characters long.
const keyBytes = (key) => {
    const buf = Buffer.from(key, 'utf8')
    if (![16, 24, 32].includes(buf.length)) {
        throw new Error(`AppKey must be 16, 24 or 32 bytes for AES, got ${buf.length}`)
    }
    return buf
}

const cipherName = (buf) => `aes-${buf.length * 8}-cbc`

const encrypt = (plainText, key) => {
    if (!plainText || !String(plainText).trim() || !key) return plainText

    const k = keyBytes(key)
    const iv = crypto.randomBytes(AES_BLOCK_SIZE)
    const cipher = crypto.createCipheriv(cipherName(k), k, iv)
    const cipherBytes = Buffer.concat([cipher.update(String(plainText), 'utf8'), cipher.final()])

    return Buffer.concat([iv, cipherBytes]).toString('base64') // IV + CipherText
}

const decrypt = (cipherText, key) => {
    if (!cipherText || !String(cipherText).trim() || !key) return cipherText

    const k = keyBytes(key)
    const encryptedData = Buffer.from(String(cipherText), 'base64')
    const iv = encryptedData.subarray(0, AES_BLOCK_SIZE)
    const cipherBytes = encryptedData.subarray(AES_BLOCK_SIZE)

    const decipher = crypto.createDecipheriv(cipherName(k), k, iv)
    return Buffer.concat([decipher.update(cipherBytes), decipher.final()]).toString('utf8')
}

module.exports = { encrypt, decrypt }
