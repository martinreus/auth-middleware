package auth

import (
    "fmt"
    "github.com/dgrijalva/jwt-go"
    "github.com/mitchellh/mapstructure"
    "log"
    "net/http"
    "time"
)

/**
structure holding data for instantiation of AuthService
*/
type authService struct {
    authConfig *AuthConfig
}

/**
Constructor for authService (which is the AuthService instantiation)
*/
func NewAuthService(authConfig *AuthConfig) AuthService {
    return &authService{
        authConfig,
    }
}

/**
    Get Authentication from http.Request
 */
func (this *authService) ToAuthenticationFromRequest(r *http.Request) (*Authentication, error) {
    if cookie, cookieError := r.Cookie(this.authConfig.JWTCookieName); cookieError != nil {
        log.Println("No Authentication cookie found!")
        return nil, cookieError
    } else {
        return this.ToAuthentication(cookie)
    }
}

/**
Transforms a JWT cookie back to an authentication
*/
func (this *authService) ToAuthentication(cookie *http.Cookie) (*Authentication, error) {
    token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
        // Don't forget to validate the alg is what you expect:
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
        }

        return this.authConfig.JWTPrivateKey, nil
    })

    if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
        return this.constructAuthentication(claims)
    } else {
        if validationError, ok := err.(*jwt.ValidationError); ok {
            // if we have only a validation expired error, we allow the token to be generated
            if validationError.Errors == jwt.ValidationErrorExpired {
                authentication, conversionError := this.constructAuthentication(claims)
                if conversionError != nil {
                    return nil, conversionError
                }
                return authentication, validationError
            }
        }
        return nil, err
    }
}

func (this *authService) ToJWTCookie(authentication *Authentication) *http.Cookie {
    type JWTToken struct {
        jwt.StandardClaims
        Name        string             `json:"name,omitempty"`
        Username    string             `json:"username,omitempty"`
        Authorities []GrantedAuthority `json:"authorities,omitempty"`
    }

    token := jwt.NewWithClaims(jwt.SigningMethodHS512, JWTToken{
        jwt.StandardClaims{
            Issuer:    authentication.Issuer,
            IssuedAt:  authentication.IssuedAt,
            Subject:   authentication.Subject,
            ExpiresAt: authentication.ExpiresAt,
        },
        authentication.Name,
        authentication.Username,
        authentication.Authorities,
    })

    signedString, _ := token.SignedString(this.authConfig.JWTPrivateKey)

    return &http.Cookie{
        Name:     this.authConfig.JWTCookieName,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   60 * 60 * 24 * 30, // one month valid TODO: configurable
        Value:    signedString,
    }
}

func (this *authService) GetClearedJWTCookie() *http.Cookie {
    return &http.Cookie{
        Name:     this.authConfig.JWTCookieName,
        Path:     "/",
        HttpOnly: true,
        MaxAge:   0,
        Expires: time.Unix(0,0),
        Value:    "",
    }
}

func (this *authService) RefreshAuthentication(oldAuth *Authentication) *Authentication {
    var refreshedAuth Authentication
    now := time.Now().Unix()

    refreshedAuth = *oldAuth
    refreshedAuth.IssuedAt = now
    refreshedAuth.ExpiresAt = now + this.authConfig.TokenExpiresIn

    return &refreshedAuth
}

// --------------------------
// private stuff
// --------------------------

/**
From the claims of a jwt, create an authentication, or error if claims are not decodable
*/
func (this *authService) constructAuthentication(claims jwt.MapClaims) (*Authentication, error) {
    var auth Authentication
    // converts inner maps so that we don't have to
    error := mapstructure.Decode(claims, &auth)
    if error != nil {
        return nil, error
    }

    auth.IssuedAt = int64(this.toFloat64(claims["iat"]))
    auth.ExpiresAt = int64(this.toFloat64(claims["exp"]))
    auth.Subject = this.toString(claims["sub"])
    auth.Issuer = this.toString(claims["iss"])

    return &auth, nil

}

/**
  Converts to String, panics if not possible.
*/
func (this *authService) toString(aString interface{}) string {
    if aString == nil {
        return ""
    }
    if s, ok := aString.(string); ok {
        return s
    }
    panic(fmt.Sprintf("%v is not a string", aString))
}

/**
Converts to float, panics if not possible.
*/
func (this *authService) toFloat64(aNumber interface{}) float64 {
    if aNumber == nil {
        return 0
    }
    if convertedNumb, ok := aNumber.(float64); ok {
        return convertedNumb
    }
    panic(fmt.Sprintf("%v is not a number", aNumber))
}