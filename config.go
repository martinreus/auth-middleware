package auth

type AuthConfig struct {
    JWTPrivateKey []byte
    // expires in seconds
    TokenExpiresIn int64
    Issuer         string
    JWTCookieName  string
}


func DefaultAuthConfig() *AuthConfig {
    return &AuthConfig{
        JWTCookieName:  "JWT",
        TokenExpiresIn: 120,
        Issuer:         "AuthServer",
        JWTPrivateKey:  []byte("somethinghere"),
    }
}