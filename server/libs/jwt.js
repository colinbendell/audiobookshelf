'use strict'

/**
 * Minimal HS256 JWT implementation using node:crypto.
 *
 * Replaces the vendored jsonwebtoken/jws/jwa/buffer-equal-constant-time stack.
 * Only HS256 is supported — this codebase never uses asymmetric algorithms for
 * its own tokens (OIDC id_token validation is handled by openid-client separately).
 *
 * API is a drop-in subset of the jsonwebtoken package:
 *   sign(payload, secret, [options])  → string
 *   verify(token, secret, [options])  → payload object  (throws on invalid)
 *   verify(token, secret, [options], callback)  → void  (async form)
 */

const crypto = require('node:crypto')

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Base64url-encode a Buffer or string.
 * @param {Buffer|string} input
 * @returns {string}
 */
function b64urlEncode(input) {
  const buf = Buffer.isBuffer(input) ? input : Buffer.from(input)
  return buf.toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_')
}

/**
 * Base64url-decode a string to a Buffer.
 * @param {string} input
 * @returns {Buffer}
 */
function b64urlDecode(input) {
  // Restore standard base64 padding and characters
  const padded = input.replace(/-/g, '+').replace(/_/g, '/') + '=='.slice(0, (4 - (input.length % 4)) % 4)
  return Buffer.from(padded, 'base64')
}

const HEADER = b64urlEncode(JSON.stringify({ alg: 'HS256', typ: 'JWT' }))

/**
 * Compute the HS256 signature for "<header>.<payload>".
 * @param {string} signingInput  e.g. "eyJ....<eyJ...."
 * @param {string|Buffer} secret
 * @returns {string} base64url signature
 */
function hmacSign(signingInput, secret) {
  return b64urlEncode(crypto.createHmac('sha256', secret).update(signingInput).digest())
}

/**
 * Constant-time comparison of two strings to prevent timing attacks.
 * @param {string} a
 * @param {string} b
 * @returns {boolean}
 */
function safeEqual(a, b) {
  if (a.length !== b.length) {
    // Still run the comparison to avoid leaking length information via timing
    crypto.timingSafeEqual(Buffer.alloc(1), Buffer.alloc(1))
    return false
  }
  return crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b))
}

// ---------------------------------------------------------------------------
// Error types (mirrors jsonwebtoken's error names for catch-site compatibility)
// ---------------------------------------------------------------------------

class JsonWebTokenError extends Error {
  constructor(message) {
    super(message)
    this.name = 'JsonWebTokenError'
  }
}

class TokenExpiredError extends Error {
  constructor(message, expiredAt) {
    super(message)
    this.name = 'TokenExpiredError'
    this.expiredAt = expiredAt
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Sign a payload and return a JWT string.
 *
 * @param {Object} payload
 * @param {string|Buffer} secret
 * @param {Object} [options]
 * @param {number|string} [options.expiresIn]  seconds (number) or a string like '1h', '30d'
 * @returns {string}
 */
function sign(payload, secret, options = {}) {
  if (!secret) throw new JsonWebTokenError('secret is required')

  const now = Math.floor(Date.now() / 1000)
  const claims = Object.assign({}, payload, { iat: now })

  if (options.expiresIn !== undefined) {
    const expiresIn = options.expiresIn
    if (typeof expiresIn === 'number') {
      claims.exp = now + expiresIn
    } else if (typeof expiresIn === 'string') {
      claims.exp = now + parseTimespan(expiresIn)
    } else {
      throw new JsonWebTokenError('expiresIn must be a number or string')
    }
  }

  const encodedPayload = b64urlEncode(JSON.stringify(claims))
  const signingInput = `${HEADER}.${encodedPayload}`
  const signature = hmacSign(signingInput, secret)
  return `${signingInput}.${signature}`
}

/**
 * Verify a JWT and return its payload.
 * Throws JsonWebTokenError or TokenExpiredError on failure.
 * If a callback is provided, errors are passed to it instead of thrown.
 *
 * @param {string} token
 * @param {string|Buffer} secret
 * @param {Object|Function} [options]
 * @param {boolean} [options.ignoreExpiration=false]
 * @param {Function} [callback]  function(err, payload)
 * @returns {Object|undefined}  payload when synchronous, undefined when callback provided
 */
function verify(token, secret, options, callback) {
  // Allow verify(token, secret, callback)
  if (typeof options === 'function') {
    callback = options
    options = {}
  }
  if (!options) options = {}

  function done(err, result) {
    if (callback) {
      callback(err, result)
      return undefined
    }
    if (err) throw err
    return result
  }

  if (!token || typeof token !== 'string') {
    return done(new JsonWebTokenError('jwt must be a non-empty string'))
  }

  const parts = token.split('.')
  if (parts.length !== 3) {
    return done(new JsonWebTokenError('jwt malformed'))
  }

  const [encodedHeader, encodedPayload, receivedSig] = parts

  // Verify header
  let header
  try {
    header = JSON.parse(b64urlDecode(encodedHeader).toString())
  } catch {
    return done(new JsonWebTokenError('invalid token header'))
  }

  if (header.alg !== 'HS256') {
    return done(new JsonWebTokenError(`unsupported algorithm: ${header.alg}`))
  }

  // Verify signature
  const expectedSig = hmacSign(`${encodedHeader}.${encodedPayload}`, secret)
  if (!safeEqual(receivedSig, expectedSig)) {
    return done(new JsonWebTokenError('invalid signature'))
  }

  // Decode payload
  let payload
  try {
    payload = JSON.parse(b64urlDecode(encodedPayload).toString())
  } catch {
    return done(new JsonWebTokenError('invalid token payload'))
  }

  // Check expiration
  if (!options.ignoreExpiration && typeof payload.exp === 'number') {
    const now = Math.floor(Date.now() / 1000)
    if (now >= payload.exp) {
      return done(new TokenExpiredError('jwt expired', new Date(payload.exp * 1000)))
    }
  }

  return done(null, payload)
}

// ---------------------------------------------------------------------------
// Timespan parser (supports jsonwebtoken-compatible strings: '1h', '30d', etc.)
// ---------------------------------------------------------------------------

const TIME_UNITS = {
  s: 1,
  m: 60,
  h: 60 * 60,
  d: 60 * 60 * 24,
  w: 60 * 60 * 24 * 7
}

/**
 * Parse a timespan string like '1h', '30d', '60' into seconds.
 * @param {string} str
 * @returns {number} seconds
 */
function parseTimespan(str) {
  const match = /^(\d+)(s|m|h|d|w)?$/.exec(str)
  if (!match) throw new JsonWebTokenError(`invalid expiresIn value: "${str}"`)
  const value = parseInt(match[1], 10)
  const unit = match[2] || 's'
  return value * TIME_UNITS[unit]
}

// ---------------------------------------------------------------------------

module.exports = { sign, verify, JsonWebTokenError, TokenExpiredError }
