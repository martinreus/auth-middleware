package auth

import (
    "net/http"
)

type OrganizationalUnit struct {
    Id   int64  `json:"id,omitempty"`
    Name string `json:"name,omitempty"`
}

type GrantedAuthority struct {
    Role     string               `json:"role,omitempty"`
    OrgUnits []OrganizationalUnit `json:"orgUnits,omitempty"`
}

type Authentication struct {
    //jwt.StandardClaims
    ExpiresAt   int64              `json:"exp,omitempty"`
    IssuedAt    int64              `json:"iat,omitempty"`
    Issuer      string             `json:"iss,omitempty"`
    Subject     string             `json:"sub,omitempty"`
    Name        string             `json:"name,omitempty"`
    Username    string             `json:"username,omitempty"`
    Authorities []GrantedAuthority `json:"authorities,omitempty"`
}

type Service interface {

    ToAuthenticationFromRequest(r *http.Request) (*Authentication, error)

    /**
        Transforms a Cookie into an Authentication object, returns error if not possible, expired or not valid
     */
    ToAuthentication(cookie *http.Cookie) (*Authentication, error)

    /**
        Transforms an Authentication to a Cookie setable in a HTTP header
     */
    ToJWTCookie(authentication *Authentication) *http.Cookie

    /**
        Returns a JWT Cookie which is expired, so that a header can be cleaned for purposes of logout
     */
    GetClearedJWTCookie() *http.Cookie

    /**
        Refreshes an Authentication that is already expired but still valid. The implementation
        should assume that a refresh may only be issued if the user has not changed his password, for example.
        Other restrictions may apply for the refresh.
     */
    RefreshAuthentication(authentication *Authentication) *Authentication

    /**
      Middleware that checks if the user is in possession of a valid, non expired JWT token.
    */
    IsAuthenticated(next http.Handler) http.Handler

    /*
       Middleware for relaxed check of authentication using JWT bearer token.
       This method is used only for refreshing a valid JWT Token after it has expired.

       The standard JWT refresh tokens from the oauth specification have normally a very
       long validity time (might be configured for shorter times though...). Refresh tokens are pointless.
       Why have another kind of token if the expired one can be used to generate another fresh one?
       After all, the token is only expired, but can be verified for its integrity.

       It is of course clear that an expired token cannot be used for an API access; only for refreshing purposes.

       Furthermore, every Token Refresh also needs to be checked against the user's database;
       if, for example, the user changed its Password, it is not safe to assume that the expired token is
       safe anymore; so any alterations on the user's data automatically revokes the possibility of
       being able to refresh the expired token.
    */
    IsAuthenticatedButExpired(next http.Handler) http.Handler
}
