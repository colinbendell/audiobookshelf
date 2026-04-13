'use strict'

/**
 * Minimal JWT passport strategy and token extractor.
 *
 * Replaces the passport-jwt npm package to eliminate the transitive dependency
 * on buffer-equal-constant-time, which is incompatible with Node.js v10+.
 *
 * Only the features used by Auth.js are implemented:
 *   - ExtractJwt.fromAuthHeaderAsBearerToken()
 *   - ExtractJwt.fromUrlQueryParameter(param)
 *   - ExtractJwt.fromExtractors(array)
 *   - JwtStrategy (passport strategy, secretOrKey + ignoreExpiration options)
 */

const url = require('url')
const util = require('util')
const passport = require('passport')
const jwt = require('../jwt')

// ---------------------------------------------------------------------------
// ExtractJwt
// ---------------------------------------------------------------------------

const AUTH_HEADER = 'authorization'
const BEARER_SCHEME = 'bearer'

/**
 * Parse an HTTP Authorization header value of the form "<scheme> <value>".
 * Returns { scheme, value } or null.
 * @param {string} hdrValue
 */
function parseAuthHeader(hdrValue) {
  if (typeof hdrValue !== 'string') return null
  const matches = hdrValue.match(/(\S+)\s+(\S+)/)
  return matches ? { scheme: matches[1], value: matches[2] } : null
}

const ExtractJwt = {}

/**
 * Returns an extractor that reads the Bearer token from the Authorization header.
 * @returns {function(Request): string|null}
 */
ExtractJwt.fromAuthHeaderAsBearerToken = function () {
  return function (req) {
    if (!req.headers[AUTH_HEADER]) return null
    const params = parseAuthHeader(req.headers[AUTH_HEADER])
    if (!params || params.scheme.toLowerCase() !== BEARER_SCHEME) return null
    return params.value
  }
}

/**
 * Returns an extractor that reads the token from a URL query parameter.
 * @param {string} paramName
 * @returns {function(Request): string|null}
 */
ExtractJwt.fromUrlQueryParameter = function (paramName) {
  return function (req) {
    const parsed = url.parse(req.url, true)
    if (parsed.query && Object.prototype.hasOwnProperty.call(parsed.query, paramName)) {
      return parsed.query[paramName]
    }
    return null
  }
}

/**
 * Returns an extractor that tries each extractor in order and returns the
 * first non-null token found.
 * @param {Array<function>} extractors
 * @returns {function(Request): string|null}
 */
ExtractJwt.fromExtractors = function (extractors) {
  if (!Array.isArray(extractors)) {
    throw new TypeError('ExtractJwt.fromExtractors expects an array')
  }
  return function (req) {
    for (const extractor of extractors) {
      const token = extractor(req)
      if (token) return token
    }
    return null
  }
}

// ---------------------------------------------------------------------------
// JwtStrategy
// ---------------------------------------------------------------------------

/**
 * Passport strategy for authenticating with a JWT.
 *
 * @param {object} options
 * @param {function} options.jwtFromRequest - Extractor function (required)
 * @param {string|Buffer} options.secretOrKey - Secret or PEM key (required)
 * @param {boolean} [options.ignoreExpiration=false]
 * @param {function} verify - function(jwt_payload, done)
 */
function JwtStrategy(options, verify) {
  passport.Strategy.call(this)
  this.name = 'jwt'

  if (!options.jwtFromRequest) {
    throw new TypeError('JwtStrategy requires a jwtFromRequest option')
  }
  if (!options.secretOrKey) {
    throw new TypeError('JwtStrategy requires a secretOrKey option')
  }
  if (!verify) {
    throw new TypeError('JwtStrategy requires a verify callback')
  }

  this._jwtFromRequest = options.jwtFromRequest
  this._secretOrKey = options.secretOrKey
  this._verifOpts = {
    ignoreExpiration: !!options.ignoreExpiration
  }
  this._verify = verify
}

util.inherits(JwtStrategy, passport.Strategy)

/**
 * Authenticate a request by extracting and verifying a JWT.
 * @param {import('express').Request} req
 */
JwtStrategy.prototype.authenticate = function (req) {
  const self = this
  const token = self._jwtFromRequest(req)

  if (!token) {
    return self.fail(new Error('No auth token'))
  }

  jwt.verify(token, self._secretOrKey, self._verifOpts, function (err, payload) {
    if (err) {
      return self.fail(err)
    }

    function verified(err, user, info) {
      if (err) return self.error(err)
      if (!user) return self.fail(info)
      return self.success(user, info)
    }

    try {
      self._verify(payload, verified)
    } catch (ex) {
      self.error(ex)
    }
  })
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  JwtStrategy,
  ExtractJwt
}
