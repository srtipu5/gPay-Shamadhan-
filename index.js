const fs = require('fs')
const path = require('path')

// Minimal .env loader. Unlike process.loadEnvFile() it does NOT overwrite
// variables already present in the environment, so a blank line in .env cannot
// wipe out a real credential exported by the shell or the container.
const loadEnv = (file = path.join(__dirname, '.env')) => {
    if (!fs.existsSync(file)) return
    for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        const match = line.match(/^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/)
        if (!match) continue
        const value = match[2].trim().replace(/^(['"])(.*)\1$/, '$2')
        if (value !== '' && process.env[match[1]] === undefined) process.env[match[1]] = value
    }
}
loadEnv()

const express = require('express')
const cors = require('cors')
const bodyParser = require('body-parser')
const { randomUUID } = require('crypto')
const { withSignature, verify, buildStringA } = require('./signature')
const { Shamadhan } = require('./shamadhan')

const app = express()
const port = Number(process.env.PORT || 3000)

// Middleware setup
app.use(cors())
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

// Spec 3.2: the AppId identifies us to the platform, the AppKey signs every call.
// Never commit the AppKey -- it lives in .env only.
const APP_ID = process.env.SHAMADHAN_APP_ID || ''
const APP_KEY = process.env.SHAMADHAN_APP_KEY || ''
const MERCHANT_ID = process.env.SHAMADHAN_MERCHANT_ID || ''
const COUNTER_NO = process.env.SHAMADHAN_COUNTER_NO || ''

const VERSION = '1.0'
const SIGN_TYPE = 'SHA256'

const shamadhan = new Shamadhan()

// Guid.NewGuid().ToString("N") -- 32 hex chars, no dashes.
const newGuid = () => randomUUID().replace(/-/g, '')

// DateTime.Now formats used by the platform.
const pad = (n, len = 2) => String(n).padStart(len, '0')
const parts = (d = new Date()) => ({
    yyyyMMdd: `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}`,
    HHmmss: `${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`,
})
const yyyyMMdd = () => parts().yyyyMMdd
const HHmmss = () => parts().HHmmss
const yyyyMMddHHmmss = () => {
    const p = parts()
    return `${p.yyyyMMdd}${p.HHmmss}`
}

// Every request carries the same four identity fields.
const envelope = () => ({
    version: VERSION,
    appId: APP_ID,
    signType: SIGN_TYPE,
    requestId: newGuid(),
    requestTime: yyyyMMddHHmmss(),
})

const send = (res, fn) =>
    fn().then(
        (payload) => res.json(payload),
        (error) => {
            console.error('Error:', error.message)
            res.status(500).json({ error: error.message })
        }
    )

// --- Create Order -----------------------------------------------------------
const SUCCESS_CODE = '00000000'

const buildCreateOrder = (input = {}) => ({
    ...envelope(),
    merchantId: MERCHANT_ID,
    counterNo: COUNTER_NO,
    orderAmt: String(input.orderAmt ?? '100'),
    orderNo: input.orderNo || newGuid(),
    orderDate: yyyyMMdd(),
    orderTime: HHmmss(),
    goodsName: input.goodsName || 'goods',
    goodsDesc: input.goodsDesc || 'goods desc',
    validUnit: input.validUnit || '00',
    validNum: input.validNum || '20',
    cancelNotifyUrl: process.env.SHAMADHAN_CALLBACK_URL || '',
    failNotifyUrl: process.env.SHAMADHAN_CALLBACK_URL || '',
    succNotifyUrl: process.env.SHAMADHAN_CALLBACK_URL || '',
    bnkNotifyUrl: process.env.SHAMADHAN_NOTIFY_URL || '',
    remark: input.remark || 'remark',
})

const createOrder = async (input) => {
    const data = buildCreateOrder(input)
    const response = await shamadhan.createOrder(withSignature(data, APP_KEY))

    assertSignedByPlatform(response)

    return {
        // Echoed back so the caller can drive the status / refund calls below.
        request: {
            requestId: data.requestId,
            orderNo: data.orderNo,
            orderDate: data.orderDate,
            orderAmt: data.orderAmt,
        },
        response,
        paymentUrl: response.pagReturnUrl || null,
    }
}

// The platform signs its replies with the same AppKey. The API is plain HTTP, so
// this signature is the only thing proving pagReturnUrl really came from the
// platform -- check it before sending a customer there.
const assertSignedByPlatform = (response) => {
    if (!verify(response, APP_KEY)) {
        console.error('Response signature mismatch. Signed source was:', buildStringA(response))
        throw new Error('Response signature did not verify -- discarding the reply.')
    }
}

// Only ever redirect to an absolute http(s) URL -- never to javascript:, data:,
// or a scheme-relative URL that would land the customer somewhere else.
const isRedirectable = (url) => /^https?:\/\/[^\s]+$/i.test(String(url || ''))

app.get('/', async (req, res) => {
    try {
        const result = await createOrder(req.query)

        // ?format=json returns the payload instead of redirecting.
        if (req.query.format === 'json') return res.json(result)

        if (result.response.rspCode !== SUCCESS_CODE) {
            console.error('CreateOrder rejected:', result.response)
            return res.status(502).json(result)
        }

        if (!isRedirectable(result.paymentUrl)) {
            console.error('CreateOrder succeeded but returned no usable pagReturnUrl:', result.response)
            return res.status(502).json(result)
        }

        // 303 so the browser follows with a GET regardless of how it got here.
        res.redirect(303, result.paymentUrl)
    } catch (error) {
        console.error('Error:', error.message)
        res.status(500).json({ error: error.message })
    }
})

// --- Check Status -----------------------------------------------------------
// QryPaymentSts is the authoritative answer on an order: we sign the call and the
// platform answers us directly, so nothing in it depends on trusting a callback.
const queryPaymentStatus = (orderNo, orderDate) => {
    const checkStatusData = {
        ...envelope(),
        merchantId: MERCHANT_ID,
        orderNo,
        orderDate,
    }

    return shamadhan.queryOrderPaymentStatus(withSignature(checkStatusData, APP_KEY))
}

app.get('/payment-status', (req, res) => {
    const { orderNo, orderDate } = req.query
    if (!orderNo || !orderDate) {
        return res.status(400).json({ error: 'orderNo and orderDate are required' })
    }

    send(res, () => queryPaymentStatus(orderNo, orderDate))
})

// --- Refund Order -----------------------------------------------------------
app.post('/refund', (req, res) => {
    const { originOrderNo, originOrderDate, refundAmt, refundReason } = req.body || {}
    if (!originOrderNo || !originOrderDate || !refundAmt) {
        return res.status(400).json({
            error: 'originOrderNo, originOrderDate and refundAmt are required',
        })
    }

    const refundOrderData = {
        ...envelope(),
        merchantId: MERCHANT_ID,
        originOrderNo,
        originOrderDate,
        refundOrderNo: newGuid(),
        refundOrderDate: yyyyMMdd(),
        refundAmt: String(refundAmt),
        refundReason: refundReason || 'Pass',
    }

    send(res, async () => ({
        request: {
            refundOrderNo: refundOrderData.refundOrderNo,
            refundOrderDate: refundOrderData.refundOrderDate,
        },
        response: await shamadhan.refundOrder(withSignature(refundOrderData, APP_KEY)),
    }))
})

// --- Refund Status ----------------------------------------------------------
app.get('/refund-status', (req, res) => {
    const { refundOrderNo, refundOrderDate } = req.query
    if (!refundOrderNo) {
        return res.status(400).json({ error: 'refundOrderNo is required' })
    }

    // Note: the reference sample omits merchantId on this call.
    const refundStatusData = {
        ...envelope(),
        refundOrderNo,
        refundOrderDate: refundOrderDate || yyyyMMdd(),
    }

    send(res, () => shamadhan.queryRefundStatus(withSignature(refundStatusData, APP_KEY)))
})

// --- Payment notification ---------------------------------------------------
// Point PG_SUCC_NOTIFY_URL / PG_FAIL_NOTIFY_URL / PG_CANCEL_NOTIFY_URL / PG_BNK_NOTIFY_URL
// here. The callback is treated purely as a trigger -- its contents are not
// trusted and its signature is not checked. All we take from it is the order
// number; the order's actual state comes from QryPaymentSts, which we call and
// sign ourselves.
// Express parses query strings as application/x-www-form-urlencoded, which turns
// every '+' into a space, so decode the raw query ourselves instead --
// decodeURIComponent leaves '+' alone and still handles a properly %-encoded value.
const parseRawQuery = (originalUrl) => {
    const qs = originalUrl.slice(originalUrl.indexOf('?') + 1)
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

const handleNotification = (req, res) => {
    // The platform sends the callback as a GET query string; POST is accepted too
    // in case a different notify URL is configured to use it.
    const data = req.method === 'GET' ? parseRawQuery(req.originalUrl) : req.body || {}

    console.log('Received notification:', data)
    console.log('Raw callback:', req.originalUrl)

    const { orderNo } = data
    if (!orderNo) {
        console.error('Notification carried no orderNo:', req.originalUrl)
        return res.status(400).json({ error: 'orderNo is missing from the notification' })
    }

    send(res, async () => {
        const status = await queryPaymentStatus(orderNo, data.orderDate || yyyyMMdd())
        console.log(`Order ${orderNo} payment status:`, status)
        return status
    })
}

app.get('/notify', handleNotification)
app.get('/notify-bank', handleNotification)

app.listen(port, () => {
    if (!APP_ID || !APP_KEY || !MERCHANT_ID) {
        console.warn('Warning: PG_APP_ID / PG_APP_KEY / PG_MERCHANT_ID are not all set in .env')
    }
    console.log(`Example app listening at http://127.0.0.1:${port}`)
})
