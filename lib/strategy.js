const util = require('util')
const passport = require('passport-strategy')

function NonceStrategy(options, verify) {
  passport.Strategy.call(this)
  this.name = 'nonce'

  // Required
  this._clientHeaderName = options.clientHeaderName
  this._nonceHeaderName = options.nonceHeaderName
  this._tokenHeaderName = options.tokenHeaderName
  this._clientSecrets = options.clientSecrets

  // Optionals
  this._expirationSeconds = options.expirationSeconds || 300
  this._toleranceSeconds = options.toleranceSeconds || 60

  if (!this._clientHeaderName) {
    throw new TypeError('Nonce Strategy requires client header name')
  }
  if (!this._nonceHeaderName) {
    throw new TypeError('Nonce Strategy requires nonce header name')
  }
  if (!this._tokenHeaderName) {
    throw new TypeError('Nonce Strategy requires token header name')
  }
  if (!this._clientSecrets) {
    throw new TypeError('Nonce Strategy requires client secrets hash')
  }
}

util.inherits(NonceStrategy, Strategy)

NonceStrategy.prototype.authenticate = function(req, options) {
  const client = req.headers[this._clientHeaderName]
  const nonce = req.headers[this._nonceHeaderName]
  const token = req.headers[this._tokenHeaderName]
  const secret = this._clientSecrets[client]

  if (nonce && nonce.indexOf('|') === -1) {
    this.fail(new Error('Nonce in wrong format'))
  }

  const timestamp = nonce.split('|')[0]

  const now = Math.floor(Date.now()/1000) + 1000000;

  if(timestamp >= now + this._toleranceSeconds){
    this.fail(new Error('API auth_token timestamp is too far in the future'))
  } else if (timestamp < now - this._expirationSeconds){
    this.fail(new Error('API auth_token has expired'))
  }

  const hash = crypto.createHash('sha256');
  const auth_token = hash.update(String(nonce) + String(secret)).digest('hex');

  if (!token || token !== auth_token) {
    this.fail(new Error('auth_token is missing or not valid'))
  }

  this.success({
    name: client,
    timestamp
  })
}

module.exports = NonceStrategy
