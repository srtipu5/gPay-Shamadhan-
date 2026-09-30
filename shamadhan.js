const axios = require('axios')

// Port of the Shamadhan client (C# reference implementation).
const BASE_URL = process.env.PG_BASE_URL || 'http://161.248.247.249:8084/opp/Ecommerce'

const ENDPOINTS = {
    createOrder: 'CreateOrder.djson',
    queryOrderPaymentStatus: 'QryPaymentSts.djson',
    refundOrder: 'RefundOrder.djson',
    queryRefundStatus: 'QryRefundSts.djson',
}

class Shamadhan {
    constructor(client) {
        this.client = client || axios.create({
            baseURL: BASE_URL,
            timeout: Number(process.env.PG_TIMEOUT_MS || 30000),
            headers: { 'Content-Type': 'application/json; charset=utf-8' },
        })
    }

    async post(endpoint, jsonData) {
        try {
            const response = await this.client.post(`/${endpoint}`, jsonData)
            return response.data
        } catch (error) {
            if (error.response) {
                throw new Error(
                    `${endpoint} returned ${error.response.status}: ${JSON.stringify(error.response.data)}`
                )
            }
            if (error.code === 'ECONNABORTED') {
                throw new Error(`The request to ${endpoint} timed out.`)
            }
            throw new Error(`Network error while calling ${endpoint}: ${error.message}`)
        }
    }

    createOrder(jsonData) {
        return this.post(ENDPOINTS.createOrder, jsonData)
    }

    queryOrderPaymentStatus(jsonData) {
        return this.post(ENDPOINTS.queryOrderPaymentStatus, jsonData)
    }

    refundOrder(jsonData) {
        return this.post(ENDPOINTS.refundOrder, jsonData)
    }

    queryRefundStatus(jsonData) {
        return this.post(ENDPOINTS.queryRefundStatus, jsonData)
    }
}

module.exports = { Shamadhan, ENDPOINTS, BASE_URL }
