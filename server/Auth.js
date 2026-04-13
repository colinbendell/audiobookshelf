const { Request, Response, NextFunction } = require('express')

const Database = require('./Database')
const Logger = require('./Logger')
const TokenManager = require('./auth/TokenManager')
const LocalAuthStrategy = require('./auth/LocalAuthStrategy')
const OidcAuthStrategy = require('./auth/OidcAuthStrategy')

const RateLimiterFactory = require('./utils/rateLimiterFactory')
const { escapeRegExp } = require('./utils')
const { verify: jwtVerify } = require('./libs/jwt')

/**
 * @class Class for handling all the authentication related functionality.
 */
class Auth {
  constructor() {
    const escapedRouterBasePath = escapeRegExp(global.RouterBasePath)
    this.ignorePatterns = [new RegExp(`^(${escapedRouterBasePath}/api)?/items/[^/]+/cover$`), new RegExp(`^(${escapedRouterBasePath}/api)?/authors/[^/]+/image$`)]

    /** @type {import('express-rate-limit').RateLimitRequestHandler} */
    this.authRateLimiter = RateLimiterFactory.getAuthRateLimiter()

    this.tokenManager = new TokenManager()
    this.localAuthStrategy = new LocalAuthStrategy()
    this.oidcAuthStrategy = new OidcAuthStrategy()
  }

  /**
   * Checks if the request should not be authenticated.
   * @param {Request} req
   * @returns {boolean}
   */
  authNotNeeded(req) {
    return req.method === 'GET' && this.ignorePatterns.some((pattern) => pattern.test(req.path))
  }

  /**
   * Middleware to conditionally apply middleware only when auth is needed.
   * @param {function} middleware
   */
  ifAuthNeeded(middleware) {
    return (req, res, next) => {
      if (this.authNotNeeded(req)) {
        return next()
      }
      middleware(req, res, next)
    }
  }

  /**
   * Session-based user restoration middleware.
   * Reads userId from the session and loads the user onto req.user.
   * Replaces passport.session() + deserializeUser.
   * @param {Request} req
   * @param {Response} res
   * @param {function} next
   */
  async sessionMiddleware(req, res, next) {
    if (req.session?.userId) {
      try {
        req.user = await Database.userModel.getUserById(req.session.userId)
      } catch (err) {
        Logger.error('[Auth] Failed to load user from session', err)
      }
    }
    next()
  }

  /**
   * Middleware to authenticate API requests via JWT (Bearer token or ?token= query param).
   * Sets req.user on success, sends 401 on failure.
   * @param {Request} req
   * @param {Response} res
   * @param {NextFunction} next
   */
  isAuthenticated(req, res, next) {
    const token = this._extractToken(req)
    if (!token) {
      return res.status(401).json({ error: 'No auth token' })
    }

    let payload
    try {
      payload = jwtVerify(token, TokenManager.TokenSecret, { ignoreExpiration: true })
    } catch {
      return res.status(401).json({ error: 'Invalid token' })
    }

    this.tokenManager.jwtAuthCheck(payload, (err, user) => {
      if (err) {
        Logger.error('[Auth] JWT auth error', err)
        return res.status(401).json({ error: 'Unauthorized' })
      }
      if (!user) {
        return res.status(401).json({ error: 'Unauthorized' })
      }
      req.user = user
      next()
    })
  }

  /**
   * Extract a JWT from the request.
   * Checks Authorization: Bearer header first, then ?token= query param.
   * @param {Request} req
   * @returns {string|null}
   */
  _extractToken(req) {
    const authHeader = req.headers['authorization']
    if (authHeader) {
      const match = authHeader.match(/^[Bb]earer\s+(\S+)$/)
      if (match) return match[1]
    }
    if (req.query?.token) return req.query.token
    return null
  }

  /**
   * Function to generate a jwt token for a given user
   * TODO: Old method with no expiration
   * @deprecated
   *
   * @param {{ id:string, username:string }} user
   * @returns {string}
   */
  generateAccessToken(user) {
    return this.tokenManager.generateAccessToken(user)
  }

  /**
   * Invalidate all JWT sessions for a given user
   * If user is current user and refresh token is valid, rotate tokens for the current session
   *
   * @param {import('./models/User')} user
   * @param {Request} req
   * @param {Response} res
   * @returns {Promise<string>} accessToken only if user is current user and refresh token is valid
   */
  async invalidateJwtSessionsForUser(user, req, res) {
    return this.tokenManager.invalidateJwtSessionsForUser(user, req, res)
  }

  /**
   * Return the login info payload for a user
   *
   * @param {import('./models/User')} user
   * @returns {Promise<Object>} jsonPayload
   */
  async getUserLoginResponsePayload(user) {
    const libraryIds = await Database.libraryModel.getAllLibraryIds()
    return {
      user: user.toOldJSONForBrowser(),
      userDefaultLibraryId: user.getDefaultLibraryId(libraryIds),
      serverSettings: Database.serverSettings.toJSONForBrowser(),
      ereaderDevices: Database.emailSettings.getEReaderDevices(user),
      Source: global.Source
    }
  }

  // #region Auth strategies

  /**
   * Initializes all authentication strategies.
   */
  async initAuth() {
    if (global.ServerSettings.authActiveAuthMethods.includes('local')) {
      this.localAuthStrategy.init()
    }
    if (global.ServerSettings.authActiveAuthMethods.includes('openid')) {
      this.oidcAuthStrategy.init()
    }
  }

  /**
   * Unuse strategy
   * @param {string} name
   */
  unuseAuthStrategy(name) {
    if (name === 'openid') {
      this.oidcAuthStrategy.unuse()
    } else if (name === 'local') {
      this.localAuthStrategy.unuse()
    } else {
      Logger.error('[Auth] Invalid auth strategy ' + name)
    }
  }

  /**
   * Use strategy
   * @param {string} name
   */
  useAuthStrategy(name) {
    if (name === 'openid') {
      this.oidcAuthStrategy.init()
    } else if (name === 'local') {
      this.localAuthStrategy.init()
    } else {
      Logger.error('[Auth] Invalid auth strategy ' + name)
    }
  }

  /**
   * Returns if the given auth method is API based.
   * @param {string} authMethod
   * @returns {boolean}
   */
  isAuthMethodAPIBased(authMethod) {
    return ['api', 'openid-mobile'].includes(authMethod)
  }

  /**
   * Stores the client's choice of login callback method in temporary cookies.
   *
   * The `authMethod` parameter specifies the authentication strategy and can have the following values:
   * - 'local': Standard authentication,
   * - 'api': Authentication for API use
   * - 'openid': OpenID authentication directly over web
   * - 'openid-mobile': OpenID authentication, but done via an mobile device
   *
   * @param {Request} req
   * @param {Response} res
   * @param {string} authMethod - The authentication method, default is 'local'.
   * @returns {Object|null} - Returns error object if validation fails, null if successful
   */
  paramsToCookies(req, res, authMethod = 'local') {
    const TWO_MINUTES = 120000 // 2 minutes in milliseconds
    const callback = req.query.redirect_uri || req.query.callback

    // Additional handling for non-API based authMethod
    if (!this.isAuthMethodAPIBased(authMethod)) {
      // Store 'auth_state' if present in the request
      if (req.query.state) {
        res.cookie('auth_state', req.query.state, { maxAge: TWO_MINUTES, httpOnly: true })
      }

      // Validate and store the callback URL
      if (!callback) {
        res.status(400).send({ message: 'No callback parameter' })
        return { error: 'No callback parameter' }
      }

      // Security: Validate callback URL is same-origin only
      if (!this.oidcAuthStrategy.isValidWebCallbackUrl(callback, req)) {
        Logger.warn(`[Auth] Rejected invalid callback URL: ${callback}`)
        res.status(400).send({ message: 'Invalid callback URL - must be same-origin' })
        return { error: 'Invalid callback URL - must be same-origin' }
      }

      res.cookie('auth_cb', callback, { maxAge: TWO_MINUTES, httpOnly: true })
    }

    // Store the authentication method
    Logger.debug(`[Auth] paramsToCookies: setting auth_method cookie to ${authMethod}`)
    res.cookie('auth_method', authMethod, { maxAge: 1000 * 60 * 60 * 24 * 365 * 10, httpOnly: true })
    return null
  }

  /**
   * Informs the client in the right mode about a successful login and the token
   * (client's choice is restored from cookies).
   *
   * @param {Request} req
   * @param {Response} res
   */
  async handleLoginSuccessBasedOnCookie(req, res) {
    const isApiBased = this.isAuthMethodAPIBased(req.cookies.auth_method)
    Logger.debug(`[Auth] handleLoginSuccessBasedOnCookie: isApiBased: ${isApiBased}, auth_method: ${req.cookies.auth_method}`)
    const userResponse = await this.handleLoginSuccess(req, res, isApiBased)

    if (isApiBased) {
      res.json(userResponse)
    } else {
      if (req.cookies.auth_cb) {
        let stateQuery = req.cookies.auth_state ? `&state=${req.cookies.auth_state}` : ''
        // TODO: Temporarily continue sending the old token as setToken
        res.redirect(302, `${req.cookies.auth_cb}?setToken=${userResponse.user.token}&accessToken=${userResponse.user.accessToken}${stateQuery}`)
      } else {
        res.status(400).send('No callback or already expired')
      }
    }
  }

  /**
   * After login success from local or oidc.
   * Saves the user id to the session and generates tokens.
   *
   * @param {Request} req
   * @param {Response} res
   * @param {boolean} returnTokens
   */
  async handleLoginSuccess(req, res, returnTokens = false) {
    // Save user id to session (replaces passport serializeUser / req.logIn)
    req.session.userId = req.user.id

    const { accessToken, refreshToken } = await this.tokenManager.createTokensAndSession(req.user, req)

    const userResponse = await this.getUserLoginResponsePayload(req.user)

    userResponse.user.refreshToken = returnTokens ? refreshToken : null
    userResponse.user.accessToken = accessToken

    Logger.debug(`[Auth] handleLoginSuccess: returnTokens: ${returnTokens}, isRefreshTokenInResponse: ${!!userResponse.user.refreshToken}`)

    if (!returnTokens) {
      this.tokenManager.setRefreshTokenCookie(req, res, refreshToken)
    }

    return userResponse
  }

  // #region Auth routes
  /**
   * Creates all (express) routes required for authentication.
   *
   * @param {import('express').Router} router
   */
  async initAuthRoutes(router) {
    // Local strategy login route (takes username and password)
    router.post('/login', this.authRateLimiter, async (req, res) => {
      const { username, password } = req.body

      const user = await this.localAuthStrategy.verifyCredentials(req, username, password)
      if (!user) {
        return res.status(401).json({ error: 'Invalid username or password' })
      }

      const returnTokens = req.headers['x-return-tokens'] === 'true'
      req.user = user
      const userResponse = await this.handleLoginSuccess(req, res, returnTokens)
      res.json(userResponse)
    })

    // Refresh token route
    router.post('/auth/refresh', this.authRateLimiter, async (req, res) => {
      let refreshToken = req.cookies.refresh_token

      let shouldReturnRefreshToken = false
      if (req.headers['x-refresh-token']) {
        refreshToken = req.headers['x-refresh-token']
        shouldReturnRefreshToken = true
      }

      if (!refreshToken) {
        Logger.error(`[Auth] Failed to refresh token. No refresh token provided`)
        return res.status(401).json({ error: 'No refresh token provided' })
      }

      Logger.debug(`[Auth] refreshing token. shouldReturnRefreshToken: ${shouldReturnRefreshToken}`)

      const refreshResponse = await this.tokenManager.handleRefreshToken(refreshToken, req, res)
      if (refreshResponse.error) {
        return res.status(401).json({ error: refreshResponse.error })
      }

      const userResponse = await this.getUserLoginResponsePayload(refreshResponse.user)

      userResponse.user.accessToken = refreshResponse.accessToken
      userResponse.user.refreshToken = shouldReturnRefreshToken ? refreshResponse.refreshToken : null
      res.json(userResponse)
    })

    // openid strategy login route (this redirects to the configured openid login provider)
    router.get('/auth/openid', this.authRateLimiter, (req, res) => {
      const authorizationUrlResponse = this.oidcAuthStrategy.getAuthorizationUrl(req)

      if (authorizationUrlResponse.error) {
        return res.status(authorizationUrlResponse.status).send(authorizationUrlResponse.error)
      }

      const cookieResult = this.paramsToCookies(req, res, authorizationUrlResponse.isMobileFlow ? 'openid-mobile' : 'openid')
      if (cookieResult && cookieResult.error) {
        return // Response already sent by paramsToCookies
      }

      res.redirect(authorizationUrlResponse.authorizationUrl)
    })

    // This will be the oauth2 callback route for mobile clients
    // It will redirect to an app-link like audiobookshelf://oauth
    router.get('/auth/openid/mobile-redirect', this.authRateLimiter, (req, res) => this.oidcAuthStrategy.handleMobileRedirect(req, res))

    // openid strategy callback route (this receives the token from the configured openid login provider)
    router.get(
      '/auth/openid/callback',
      this.authRateLimiter,
      async (req, res, next) => {
        const isMobile = !!req.session?.oidc?.mobile

        function handleAuthError(errorCode, errorMessage, logMessage, response) {
          Logger.error(JSON.stringify(logMessage, null, 2))
          if (response) {
            const header = response.req?._header.replace(/Authorization: [^\r\n]*/i, 'Authorization: REDACTED')
            Logger.debug(header + '\n' + JSON.stringify(response.body, null, 2))
          }
          if (isMobile) {
            return res.status(errorCode).send(errorMessage)
          } else {
            return res.redirect(`/login?error=${encodeURIComponent(errorMessage)}&autoLaunch=0`)
          }
        }

        try {
          const user = await this.oidcAuthStrategy.handleCallback(req)
          if (!user) {
            return handleAuthError(401, 'Unauthorized', '[Auth] No user returned from openid callback')
          }

          req.user = user
          // Save user id to session (replaces req.logIn / passport serializeUser)
          req.session.userId = user.id
          res.cookie('openid_id_token', user.openid_id_token, { maxAge: 1000 * 60 * 60 * 24 * 365 * 10, httpOnly: true, secure: true, sameSite: 'Strict' })
          next()
        } catch (err) {
          return handleAuthError(500, 'Error in callback', `[Auth] Error in openid callback - ${err}`, err?.response)
        }
      },
      // on a successful login: read the cookies and react like the client requested (callback or json)
      this.handleLoginSuccessBasedOnCookie.bind(this)
    )

    /**
     * Helper route used to auto-populate the openid URLs in config/authentication
     * Takes an issuer URL as a query param and requests the config data at "/.well-known/openid-configuration"
     *
     * @example /auth/openid/config?issuer=http://192.168.1.66:9000/application/o/audiobookshelf/
     */
    router.get('/auth/openid/config', this.authRateLimiter, this.isAuthenticated.bind(this), async (req, res) => {
      if (!req.user.isAdminOrUp) {
        Logger.error(`[Auth] Non-admin user "${req.user.username}" attempted to get issuer config`)
        return res.sendStatus(403)
      }

      if (!req.query.issuer || typeof req.query.issuer !== 'string') {
        return res.status(400).send("Invalid request. Query param 'issuer' is required")
      }

      const openIdIssuerConfig = await this.oidcAuthStrategy.getIssuerConfig(req.query.issuer)
      if (openIdIssuerConfig.error) {
        return res.status(openIdIssuerConfig.status).send(openIdIssuerConfig.error)
      }

      res.json(openIdIssuerConfig)
    })

    // Logout route
    router.post('/logout', async (req, res) => {
      const refreshToken = req.cookies.refresh_token || req.headers['x-refresh-token']

      res.clearCookie('refresh_token', { path: '/' })

      if (refreshToken) {
        await this.tokenManager.invalidateRefreshToken(refreshToken)
      } else {
        Logger.info(`[Auth] logout: No refresh token on request`)
      }

      const authMethod = req.cookies.auth_method
      res.clearCookie('auth_method')

      let logoutUrl = null
      if (authMethod === 'openid' || authMethod === 'openid-mobile') {
        logoutUrl = this.oidcAuthStrategy.getEndSessionUrl(req, req.cookies.openid_id_token, authMethod)
        res.clearCookie('openid_id_token')
      }

      // Destroy the express session (replaces req.logout())
      req.session.destroy((err) => {
        if (err) {
          Logger.error('[Auth] Failed to destroy session on logout', err)
          return res.sendStatus(500)
        }
        res.send({ redirect_url: logoutUrl })
      })
    })
  }
  // #endregion
}

module.exports = Auth
