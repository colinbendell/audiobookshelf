const Database = require('../Database')
const Logger = require('../Logger')

const bcrypt = require('../libs/bcryptjs')
const requestIp = require('../libs/requestIp')

/**
 * Local authentication strategy using username/password
 */
class LocalAuthStrategy {
  constructor() {
    this.enabled = false
  }

  /**
   * Enable the local strategy
   */
  init() {
    this.enabled = true
  }

  /**
   * Disable the local strategy
   */
  unuse() {
    this.enabled = false
  }

  /**
   * Verify user credentials.
   * Returns the user on success, null on failure.
   *
   * @param {import('express').Request} req
   * @param {string} username
   * @param {string} password
   * @returns {Promise<import('../models/User')|null>}
   */
  async verifyCredentials(req, username, password) {
    if (!username) {
      this.logFailedLoginAttempt(req, username, 'No username provided')
      return null
    }

    // Load the user given its username
    const user = await Database.userModel.getUserByUsername(username.toLowerCase())

    if (!user?.isActive) {
      if (user) {
        this.logFailedLoginAttempt(req, user.username, 'User is not active')
      } else {
        this.logFailedLoginAttempt(req, username, 'User not found')
      }
      return null
    }

    // Check passwordless root user
    if (user.type === 'root' && !user.pash) {
      if (password) {
        // deny login
        this.logFailedLoginAttempt(req, user.username, 'Root user has no password set')
        return null
      }
      // approve login
      Logger.info(`[LocalAuth] User "${user.username}" logged in from ip ${requestIp.getClientIp(req)}`)
      return user
    } else if (!user.pash) {
      this.logFailedLoginAttempt(req, user.username, 'User has no password set. Might have been created with OpenID')
      return null
    }

    // Check password match
    const compare = await bcrypt.compare(password, user.pash)
    if (compare) {
      Logger.info(`[LocalAuth] User "${user.username}" logged in from ip ${requestIp.getClientIp(req)}`)
      return user
    }

    // deny login
    this.logFailedLoginAttempt(req, user.username, 'Invalid password')
    return null
  }

  /**
   * Log failed login attempts
   * @param {import('express').Request} req
   * @param {string} username
   * @param {string} message
   */
  logFailedLoginAttempt(req, username, message) {
    if (!req || !username || !message) return
    Logger.error(`[LocalAuth] Failed login attempt for username "${username}" from ip ${requestIp.getClientIp(req)} (${message})`)
  }

  /**
   * Hash a password with bcrypt
   * @param {string} password
   * @returns {Promise<string>} hash
   */
  hashPassword(password) {
    return new Promise((resolve) => {
      bcrypt.hash(password, 8, (err, hash) => {
        if (err) {
          resolve(null)
        } else {
          resolve(hash)
        }
      })
    })
  }

  /**
   * Compare password with user's hashed password
   * @param {string} password
   * @param {import('../models/User')} user
   * @returns {Promise<boolean>}
   */
  comparePassword(password, user) {
    if (user.type === 'root' && !password && !user.pash) return true
    if (!password || !user.pash) return false
    return bcrypt.compare(password, user.pash)
  }

  /**
   * Change user password
   * @param {import('../models/User')} user
   * @param {string} password
   * @param {string} newPassword
   */
  async changePassword(user, password, newPassword) {
    // Only root can have an empty password
    if (user.type !== 'root' && !newPassword) {
      return {
        error: 'Invalid new password - Only root can have an empty password'
      }
    }

    // Check password match
    const compare = await this.comparePassword(password, user)
    if (!compare) {
      return {
        error: 'Invalid password'
      }
    }

    let pw = ''
    if (newPassword) {
      pw = await this.hashPassword(newPassword)
      if (!pw) {
        return {
          error: 'Hash failed'
        }
      }
    }

    try {
      await user.update({ pash: pw })
      Logger.info(`[LocalAuth] User "${user.username}" changed password`)
      return {
        success: true
      }
    } catch (error) {
      Logger.error(`[LocalAuth] User "${user.username}" failed to change password`, error)
      return {
        error: 'Unknown error'
      }
    }
  }
}

module.exports = LocalAuthStrategy
