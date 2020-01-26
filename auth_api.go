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

// Service deals with all intricacies related to JWT tokens and translating them to an Authentication
type Service interface {
	FromRequest(r *http.Request) (*Authentication, error)

	// FromCookie Transforms a Cookie into an Authentication object, returns error if not possible, expired or not valid
	FromCookie(cookie *http.Cookie) (*Authentication, error)

	// ToJWTCookie Transforms an Authentication to a Cookie setable in a HTTP header
	ToJWTCookie(authentication *Authentication) *http.Cookie

	// GetClearedJWTCookie Returns a JWT Cookie which is expired, so that a header can be cleaned for purposes of logout
	GetClearedJWTCookie() *http.Cookie

	/*
	  RefreshAuthentication Refreshes an Authentication that is already expired but still valid. The implementation
	  should assume that a refresh may only be issued if the user has not changed his password, for example.
	  Other restrictions may apply for the refresh.
	*/
	RefreshAuthentication(authentication *Authentication) (*Authentication, error)
}

// Middleware can be used in http handlers to check user authentication and authorization
type Middleware interface {

	// IsAuthenticated Middleware that checks if the user is in possession of a valid, short lived, non expired JWT token.
	IsAuthenticated(next http.Handler) http.Handler

	/*
	  Middleware for relaxed check of authentication using JWT bearer token.
	  This method is used only for refreshing a valid JWT Token after it has expired.

	  Refreshing an expired token is allowed here to avoid having to deal with refresh tokens (as defined in OAuth
	  specification). Refreshing a token of course involves checking if the user has not altered its password,
	  or checking for a security timestamp; that means that if a JWT has been exposed by any means, we may "block"
	  refreshes of all the tokens out in the wild, and the user is forced to login again.
	*/
	IsAuthenticatedButExpired(next http.Handler) http.Handler

	/**
	  Middleware checks that user is in possession of a valid, non expired JWT Token and also has at least one
	  of the given Roles assigned to him.
	*/
	HasAnyRole(roles ...string) func(next http.Handler) http.Handler
}
