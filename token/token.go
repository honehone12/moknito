package token

const HMAC_KEY_LEN = 32
const HMAC_KEY_ENV_LEN = 44
const HMAC_SIGNATURE_LEN = 32

const RSA_PRIV_KEY_LEN = 2048

const TOKEN_TYPE_AUTHENTICATION = "authentication"
const TOKEN_TYPE_AUTHORIZATION = "authorization"
const TOKEN_TYPE_REFRESH = "refresh"
const BUNDLE_TOKEN_TYPE_BEARER = "bearer"
const AUTHENTICATED_TOKEN_VERSION = "0.0.1"
