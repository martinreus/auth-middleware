package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/mitchellh/mapstructure"
	"net/http"
	"time"
)

// structure holding data for instantiation of Service
type authService struct {
	authConfig Config
}

// New builds an authService instance given the config object
func New(authConfig Config) authService {
	return authService{
		authConfig,
	}
}

// NewWithDefaults creates a new authService with a private key
func NewWithDefaults(privateKey string) authService {
	config := DefaultAuthConfig([]byte(privateKey))
	return authService{
		config,
	}
}

// FromRequest from http.Request transforms a cookie in a request in an Authentication instance
func (service authService) FromRequest(r *http.Request) (*Authentication, error) {
	if cookie, cookieError := r.Cookie(service.authConfig.JWTCookieName); cookieError != nil {
		return nil, cookieError
	} else {
		return service.FromCookie(cookie)
	}
}


// FromCookie transforms a JWT cookie back to an authentication
func (service authService) FromCookie(cookie *http.Cookie) (*Authentication, error) {
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		// Don't forget to validate the alg is what you expect:
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return service.authConfig.JWTPrivateKey, nil
	})

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return service.constructAuthentication(claims)
	} else {
		if validationError, ok := err.(*jwt.ValidationError); ok {
			// if we have only a validation expired error, we allow the token to be generated
			if validationError.Errors == jwt.ValidationErrorExpired {
				authentication, conversionError := service.constructAuthentication(claims)
				if conversionError != nil {
					return nil, conversionError
				}
				return authentication, validationError
			}
		}
		return nil, err
	}
}

// ToJWTCookie transforms and Authentication into a Cookie
func (service authService) ToJWTCookie(authentication *Authentication) *http.Cookie {
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

	signedString, _ := token.SignedString(service.authConfig.JWTPrivateKey)

	return &http.Cookie{
		Name:     service.authConfig.JWTCookieName,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   60 * 60 * 24 * 30, // one month valid TODO: configurable
		Value:    signedString,
	}
}

// GetClearedJWTCookie gets a blank cookie with a name corresponding to the provided config
func (service authService) GetClearedJWTCookie() *http.Cookie {
	return &http.Cookie{
		Name:     service.authConfig.JWTCookieName,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   0,
		Expires:  time.Unix(0, 0),
		Value:    "",
	}
}

// RefreshAuthentication refreshes Authentication expiracy date
func (service authService) RefreshAuthentication(oldAuth *Authentication) (*Authentication, error) {
	var refreshedAuth Authentication
	now := time.Now().In(time.UTC).Unix()

	// first check if MaxRenewalTime has been reached
	if now > int64(service.authConfig.MaxRenewalTime)+oldAuth.IssuedAt {
		// if so, user is obliged to log in again, renewal of tokens is refused.
		return nil, &Error{ErrorCode: MaxRefreshTimeReached}
	}
	refreshedAuth = *oldAuth
	refreshedAuth.ExpiresAt = now + service.authConfig.TokenExpiresIn

	return &refreshedAuth, nil
}

// --------------------------
// private stuff
// --------------------------

// constructAuthentication: from the claims of a jwt, create an authentication, or error if claims are not decodable
func (service authService) constructAuthentication(claims jwt.MapClaims) (*Authentication, error) {
	var auth Authentication
	// converts inner maps so that we don't have to
	error := mapstructure.Decode(claims, &auth)
	if error != nil {
		return nil, error
	}

	auth.IssuedAt = int64(toFloat64(claims["iat"]))
	auth.ExpiresAt = int64(toFloat64(claims["exp"]))
	auth.Subject = toString(claims["sub"])
	auth.Issuer = toString(claims["iss"])

	return &auth, nil

}

// Converts to String, panics if not possible.
func toString(aString interface{}) string {
	if s, ok := aString.(string); ok {
		return s
	}
	return ""
}

/**
Converts to float, panics if not possible.
*/
func toFloat64(aNumber interface{}) float64 {
	if convertedNumb, ok := aNumber.(float64); ok {
		return convertedNumb
	}
	return 0
}
