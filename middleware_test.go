package auth

import (
    "net/http"
    "net/http/httptest"
    "testing"
)

const validTokenWithSYSTEMRole = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE3NTE4MDAwMTYsImlhdCI6MTU2MjQxMTIzMiwiaXNzIjoiQXV0aFNlcnZpY2UiLCJzdWIiOiJhdXRoLXNlcnZpY2UiLCJuYW1lIjoiYXV0aC1zZXJ2aWNlIiwidXNlcm5hbWUiOiJhdXRoLXNlcnZpY2UiLCJhdXRob3JpdGllcyI6W3sicm9sZSI6IlNZU1RFTSJ9XX0.v7I5-Zf4UASLgW4RRyIiihwE6cHnEXLwhWJxMLgLjf5GnbIKTqMnDNqhxE1gd0liNkM7_mcxNm63rbCDwIHhmw"

func TestAuthenticatedMiddlewareForExpiredToken(t *testing.T) {
    service := createAuthService("privatesigningpassowrd")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: expiredToken})

    service.IsAuthenticated(nextHandler).ServeHTTP(rr, req)

    if nextHandler.Visited {
        t.Error("Next handler should not have been called for expired JWT token")
    }
    if rr.Code != http.StatusUnauthorized {
        t.Error("Status should be unauthorized")
    }
}

func TestAuthenticatedMiddlewareForValidToken(t *testing.T) {
    service := createAuthService("privatesigningpassowrd")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: tokenValidUntil2099})

    service.IsAuthenticated(nextHandler).ServeHTTP(rr, req)

    if !nextHandler.Visited {
        t.Error("Next handler should have been called for valid JWT token")
    }
    if rr.Code == http.StatusUnauthorized {
        t.Error("Status should not be unauthorized")
    }
}

func TestHasAnyRoleMiddlewareForValidTokenButWithoutRole(t *testing.T) {
    service := createAuthService("privatesigningpassowrd")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: tokenValidUntil2099})

    service.HasAnyRole("SYSTEM")(nextHandler).ServeHTTP(rr, req)

    if nextHandler.Visited {
        t.Error("Next handler should not have been called for valid JWT without SYSTEM role")
    }
    if rr.Code != http.StatusUnauthorized {
        t.Error("Status should be unauthorized since user has no role")
    }
}

func TestHasAnyRoleMiddlewareForValidTokenAndSYSTEMRole(t *testing.T) {
    service := createAuthService("privateKey")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: validTokenWithSYSTEMRole})

    service.HasAnyRole("SYSTEM")(nextHandler).ServeHTTP(rr, req)

    if !nextHandler.Visited {
        t.Error("Next handler should have been called for valid JWT token with SYSTEM role")
    }
    if rr.Code == http.StatusUnauthorized {
        t.Error("Status should not be unauthorized")
    }
}

func TestHasAnyRoleMiddlewareForValidTokenButDifferentRoleThanExpected(t *testing.T) {
    service := createAuthService("privateKey")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: validTokenWithSYSTEMRole})

    service.HasAnyRole("USER")(nextHandler).ServeHTTP(rr, req)

    if nextHandler.Visited {
        t.Error("Next handler should not have been called for valid JWT token with other not wanted role")
    }
    if rr.Code != http.StatusUnauthorized {
        t.Error("Status should be unauthorized")
    }
}

func TestUnauthorizedForInvalidToken(t *testing.T) {
    service := createAuthService("privateKey")
    nextHandler := &nextHandler{}

    req, rr := newRequestResponseEmulation(t)

    req.AddCookie(&http.Cookie{Name: "JWT", Value: expiredToken})

    service.HasAnyRole("USER")(nextHandler).ServeHTTP(rr, req)

    if nextHandler.Visited {
        t.Error("Next handler should not have been called for valid JWT token with other not wanted role")
    }
    if rr.Code != http.StatusUnauthorized {
        t.Error("Status should be unauthorized")
    }
}

// ----- test helpers ----------------

func newRequestResponseEmulation(t *testing.T) (*http.Request, *httptest.ResponseRecorder) {
    req, err := http.NewRequest("GET", "/", nil)
    if err != nil {
        t.Fatal(err)
    }
    rr := httptest.NewRecorder()
    return req, rr
}

type nextHandler struct {
    Visited bool
}

func (this *nextHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    this.Visited = true
}

func createAuthService(key string) Service {
    return New(&Config{
        JWTPrivateKey: []byte(key),
    })
}