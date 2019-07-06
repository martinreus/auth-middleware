## Auth services and Middleware for Go applications

### How to use it

```go
package main

import (
    "github.com/gorilla/mux"
    "github.com/martinreus/auth-middleware"
)

func main() {
    r := mux.NewRouter()
    authConfig := auth.DefaultConfig()
    authMiddleware := auth.NewService(authConfig)

    api := r.PathPrefix("/api").Subrouter()
    api.HandleFunc("/user/{id}", GetUser).Methods("GET")
    api.Use(authMiddleware.IsAuthenticated)
    api.Use(authMiddleware.HasAnyRole("ADMIN", "SYSTEM"))

    http.ListenAndServe(":8000", r)
}

func GetUser(w http.ResponseWriter, r *http.Request) {...}
```

Each request will now need a valid JWT Token in order to access the get user route.

### Generating JWT's from the command line
With this library it is possible to generate JWT tokens using the provided JWT structure defined here. Just

```bash
go run cmd/jwt_generator.go
```
and read the instructions.

### TODO:
Improve

```go 
this.doc()
```
:)
