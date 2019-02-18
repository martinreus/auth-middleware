package auth

import (
    "github.com/dgrijalva/jwt-go"
    "log"
    "net/http"
)

func (this *authService) IsAuthenticated(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("Going to test authentication...", r.RequestURI)
        cookie, cookieError := r.Cookie(this.authConfig.JWTCookieName)

        if cookieError != nil || cookie == nil {
            log.Println("JWT Cookie not present or invalid")
            http.Error(w, "Unauthorized.", http.StatusUnauthorized)
            return
        }

        authentication, error := this.ToAuthentication(cookie)

        // if we have any errors,
        if error != nil || authentication == nil  {
            log.Println("Authentication failed")
            http.Error(w, "Unauthorized.", http.StatusUnauthorized)
        } else {
            // otherwise, JWT check has been successful
            next.ServeHTTP(w, r)
        }
    })
}

// TODO: add maximum delta check between expiracy and renewal.
func (this *authService) IsAuthenticatedButExpired(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        log.Println("Going to test expired authentication...", r.RequestURI)

        cookie, cookieError := r.Cookie(this.authConfig.JWTCookieName)

        if cookieError != nil {
            http.Error(w, "Unauthorized.", http.StatusUnauthorized)
            log.Println("no JWT Tooken found")
            return
        }

        _, error := this.ToAuthentication(cookie)

        // if we have any errors,
        if error != nil {
            if validationError, ok := error.(*jwt.ValidationError); ok {
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