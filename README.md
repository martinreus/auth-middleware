## Auth services and Middleware for Go applications

### How to use it

```go
package main

import (
    "github.com/gorilla/mux"
    "github.com/martinreus/csrf"
)

func main() {
    r := mux.NewRouter()
    authConfig := config.DefaultAuthConfig()
    authMiddleware := auth.NewAuthService(authConfig)

    api := r.PathPrefix("/api").Subrouter()
    api.HandleFunc("/user/{id}", GetUser).Methods("GET")
    api.Use(authMiddleware.IsAuthenticated)

    http.ListenAndServe(":8000", r)
}

func GetUser(w http.ResponseWriter, r *http.Request) {...}
```

Each request will now need a valid JWT Token in order to access the get user route.

### TODO:
Improve

```go 
this.doc()
```
:)