package auth

type Config struct {
    JWTPrivateKey []byte
    // expires in seconds. Defaults to 5 minutes.
    TokenExpiresIn int64
    Issuer         string
    JWTCookieName  string
    // max allowed time in seconds, for which an expired token may be renewed. Defaults to one month
    MaxRenewalTime int
}

/**
  Default values used:

  JWTCookieName:  "JWT",
  TokenExpiresIn: 900,
  Issuer:         "AuthServer",
  MaxRenewalTime: 2592000,
*/
func DefaultAuthConfig(privateKey []byte) *Config {
    return &Config{
        JWTCookieName:  "JWT",
        TokenExpiresIn: 300, //5 minutes in seconds
        Issuer:         "AuthServer",
        JWTPrivateKey:  privateKey,
        MaxRenewalTime: 2592000, //one month in seconds
    }
}