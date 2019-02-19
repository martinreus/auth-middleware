package auth

import (
    "github.com/dgrijalva/jwt-go"
    "net/http"
    "reflect"
    "testing"
)

// issued at GMT Friday, 30. November 2018 10:00:40 (1543572040), valid until GMT: Friday, 30. November 2018 10:01:58 (1543572118)
var expiredToken = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NDM1NzIxMTgsImlhdCI6MTU0MzU3MjA0MCwiaXNzIjoiZmx5aW5nIGR1dGNobWFuIiwic3ViIjoic3VwZXJhZG1pbiIsIm5hbWUiOiJNYXJ0eSBNY0ZseSIsImF1dGhvcml0aWVzIjpbeyJyb2xlIjoiYWRtaW4iLCJvcmdVbml0cyI6W3siaWQiOjIxLCJuYW1lIjoib3JnIHVuaXQifV19XX0.ZuvEdONZiyhB2oFA8VF5bV8hCzD6Ctng43TcMFuu30vD3rcd5iR_ePQiQb-npW93SEyd7YlBjnjIA2QTnOGEvg"
// issued at GMT Friday, 30. November 2018 10:00:40 (1543572040), valid until GMT Monday, 30. November 2099 10:08:04 (4099716484)
var tokenValidUntil2099 = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjQwOTk3MTY0ODQsImlhdCI6MTU0MzU3MjA0MCwiaXNzIjoiZmx5aW5nIGR1dGNobWFuIiwic3ViIjoic3VwZXJhZG1pbiIsIm5hbWUiOiJNYXJ0eSBNY0ZseSIsInVzZXJuYW1lIjoibWFydHkiLCJhdXRob3JpdGllcyI6W3sicm9sZSI6ImFkbWluIiwib3JnVW5pdHMiOlt7ImlkIjoyMSwibmFtZSI6Im9yZyB1bml0In1dfV19.m7FA3NTVn9OLvsszRApmFb2k4xZoTVIC-RUbwE1zBaDO9V4mUjFDwNHxBqNarkVi18Qq5iAsmFAEcenWuFwCHQ"

var issuedAt = int64(1543572040)
var expiresShortlyAfter = int64(1543572118)
var expires2099 = int64(4099716484)

/**
  Should convert valid token and return no error.
*/
func TestToAuthenticationWithValidToken(t *testing.T) {
    authService := New(&Config{
        JWTPrivateKey: []byte("privatesigningpassowrd"),
    })

    expectedAuthentication := &Authentication{
        ExpiresAt: expires2099,
        Issuer:    "flying dutchman",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Username:  "marty",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    authentication, error := authService.ToAuthentication(&http.Cookie{
        Value: tokenValidUntil2099,
    })

    if !reflect.DeepEqual(authentication, expectedAuthentication) {
        t.Fail()
    }
    if error != nil {
        t.Fail()
    }
}

func TestToValidJWTTokenCookie(t *testing.T) {
    authService := New(&Config{
        JWTPrivateKey: []byte("privatesigningpassowrd"),
    })

    authentication := Authentication{
        ExpiresAt: expires2099,
        Issuer:    "flying dutchman",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Username:  "marty",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    cookie := authService.ToJWTCookie(&authentication)

    if cookie.Value != tokenValidUntil2099 {
        t.Fail()
    }
}

func TestToJWTTokenCookie(t *testing.T) {
    // given
    authService := New(&Config{
        JWTPrivateKey: []byte("privatesigningpassowrd"),
    })

    authentication := Authentication{
        ExpiresAt: expiresShortlyAfter,
        Issuer:    "flying dutchman",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    // when
    cookie := authService.ToJWTCookie(&authentication)

    // then
    if cookie.Value != expiredToken {
        t.Fail()
    }
}

func TestToAuthenticationWithExpiredAndTamperedToken(t *testing.T) {
    // actual Password in the to be tested token is different, simulating a tampered token
    authService := New(&Config{
        JWTPrivateKey: []byte("somethingSomething"),
    })

    authentication, err := authService.ToAuthentication(&http.Cookie{
        Value: expiredToken,
    })

    // authentication should be nil, since token is invalid
    if authentication != nil {
        t.Fail()
    }

    valError := err.(*jwt.ValidationError)
    // should contain signature invalid error
    if valError.Errors&jwt.ValidationErrorSignatureInvalid == 0 {
        // if not, fail test
        t.Fail()
    }
}

/**
  Should be possible to interpret expired token.
*/
func TestToAuthentication(t *testing.T) {
    // given
    authService := New(&Config{
        JWTPrivateKey: []byte("privatesigningpassowrd"),
    })

    expectedAuthentication := &Authentication{
        ExpiresAt: expiresShortlyAfter,
        Issuer:    "flying dutchman",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    // when
    authentication, validationError := authService.ToAuthentication(&http.Cookie{
        Value: expiredToken,
    })

    // then expected is equal to actual
    if !reflect.DeepEqual(authentication, expectedAuthentication) {
        t.Errorf("Expected authentication is different than one retrieved from cookie")
    }
    // and error is token expired
    if validationError, ok := validationError.(*jwt.ValidationError); ok {
        if validationError.Errors != jwt.ValidationErrorExpired {
            t.Errorf("Token should only have error 'expired'")
        }
    } else {
        t.Errorf("Token should be expired")
    }
}

func TestRefreshAuthentication(t *testing.T) {
    authService := New(&Config{
        JWTCookieName:  "JWT",
        MaxRenewalTime: 9999999999999,
    })

    authentication := &Authentication{
        Username:  "marty@mail.com",
        ExpiresAt: expiresShortlyAfter,
        Issuer:    "flying dutchman app",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    refreshAuth, _ := authService.RefreshAuthentication(authentication)

    // fail if expiracy is equal between original and refreshed token
    if refreshAuth.ExpiresAt <= authentication.ExpiresAt {
        t.Errorf("ExpiresAt should have changed its value to a time in future")
    }
    // fail if issuedAt changed; we want it to be like it was when it first was generated, so that we may
    // keep track of old issued tokens and prevent them being refreshed after a max refresh time has been reached
    if refreshAuth.IssuedAt != authentication.IssuedAt {
        t.Errorf("issuedAt has a new value; should have remained the same")
    }

    // fail if other properties are not equal. we expect that all properties have been copied as is, without modification
    if refreshAuth.Username != authentication.Username ||
        refreshAuth.Subject != authentication.Subject ||
        refreshAuth.Name != authentication.Name ||
        !reflect.DeepEqual(refreshAuth.Authorities, authentication.Authorities) {
        t.Errorf("Remaining fields should have remained unaltered")
    }
}

func TestRefreshAuthenticationFailureForMaxTimeReached(t *testing.T) {
    authService := New(&Config{
        JWTCookieName:  "JWT",
        MaxRenewalTime: 5, //5 seconds, force max renewal error
    })

    authentication := &Authentication{
        Username:  "marty@mail.com",
        ExpiresAt: expiresShortlyAfter,
        Issuer:    "flying dutchman app",
        Subject:   "superadmin",
        IssuedAt:  issuedAt,
        Name:      "Marty McFly",
        Authorities: []GrantedAuthority{
            {
                Role: "admin",
                OrgUnits: []OrganizationalUnit{
                    {Name: "org unit", Id: 21},
                },
            },
        },
    }

    _, err := authService.RefreshAuthentication(authentication)

    if authErr, castSuccess := err.(*Error); !castSuccess ||
        authErr.ErrorCode != MaxRefreshTimeReached {

        t.Errorf("Should have returned an error when refreshing; error code should be MaxRefreshTimeReached")
    }

}
