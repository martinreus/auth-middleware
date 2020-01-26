package auth

import (
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"log"
	"net/http"
)

func (service authService) IsAuthenticated(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := service.FromRequest(r); err != nil {
			http.Error(w, fmt.Sprintf("Unauthorized: %s", err.Error()), http.StatusUnauthorized)
			return
		}

		// otherwise, JWT check has been successful
		next.ServeHTTP(w, r)
	})
}

// TODO: add maximum delta check between expiracy and renewal.
func (service authService) IsAuthenticatedButExpired(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie, cookieError := r.Cookie(service.authConfig.JWTCookieName)

		if cookieError != nil {
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		}

		_, err := service.FromCookie(cookie)

		// if we have any errors,
		if err != nil {
			if validationError, ok := err.(*jwt.ValidationError); ok {
				// and if it is only expired, an has no additional errors, then we allow the next function to proceed.
				if validationError.Errors == jwt.ValidationErrorExpired {
					log.Println("Expired but valid. Proceeding to next call in chain...")
					// Call the next handler, which can be another middleware in the chain, or the final handler.
					next.ServeHTTP(w, r)
					return
				}
			}
			// otherwise, set unauthorized
			http.Error(w, "Unauthorized.", http.StatusUnauthorized)
			return
		} else {
			// otherwise, JWT check has been successful
			next.ServeHTTP(w, r)
			return
		}
	})
}

func (service authService) HasAnyRole(role ...string) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			jwtAuthentication, err := service.FromRequest(r)
			if err != nil {
				http.Error(w, fmt.Sprintf("Unauthorized: %s", err.Error()), http.StatusUnauthorized)
				return
			}

			for _, authority := range jwtAuthentication.Authorities {
				for _, roleToTest := range role {
					if authority.Role == roleToTest {
						// yay user has one of the defined roles, proceed to next middleware
						next.ServeHTTP(w, r)
						return
					}
				}
			}

			http.Error(w, fmt.Sprintf("Unauthorized: User has none of %s roles", role), http.StatusUnauthorized)
			return
		})
	}
}
