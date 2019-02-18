package auth

type Config struct {
    JWTPrivateKey []byte
    // expires in seconds
    TokenExpiresIn int64
    Issuer         string
    JWTCookieName  string
}


func DefaultAuthConfig() *Config {
    return &Config{
        JWTCookieName:  "JWT",
        TokenExpiresIn: 120,
        Issuer:         "AuthServer",
        JWTPrivateKey:  []byte("somethinghere"),
    }
}