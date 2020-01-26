package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"github.com/martinreus/auth-middleware"
	"os"
)

type Config struct {
    PrivateKey string
}

type JWTGenerateModel struct {
	// has the configuration for this authentication service. Only private key needs to be provided
	Config Config `json:"config"`
	// has the model wich will be converted to a JWT Token.
	Payload auth.Authentication `json:"payload"`
}


var exampleModel = JWTGenerateModel{
	Config: Config{
        PrivateKey: "privateKey",
	},
	Payload: auth.Authentication{
		Issuer: "anIssuer",
		Authorities: []auth.GrantedAuthority{
			{
				Role:     "USER",
				OrgUnits: nil,
			},
		},
		Name:      "name",
		Subject:   "123123-21312332345-25434-sad",
		Username:  "username",
		ExpiresAt: 44444444444444,
		IssuedAt:  33333333333333,
	},
}

func main() {
	configuration := flag.String("config", "", "Configuration for generating a JWT token")
	flag.Parse()
	if configuration == nil || *configuration == "" {
        bytes, _ := json.Marshal(exampleModel)
        fmt.Println(
		    fmt.Sprintf("Please provide a valid configuration for generating a JWT. A Valid example could be: %s. \nFind out more with -h flag", string(bytes)))
		os.Exit(0)
	}

	var jwtConfig JWTGenerateModel

	if err := json.Unmarshal([]byte(*configuration), &jwtConfig); err != nil {
		fmt.Println(fmt.Sprintf("Unable to unmarshal %s", *configuration))
		os.Exit(1)
	}

    authService := auth.New(auth.Config{JWTPrivateKey: []byte(jwtConfig.Config.PrivateKey)})

    cookie := authService.ToJWTCookie(&jwtConfig.Payload)

    fmt.Println("Generated Token:")
    fmt.Println(fmt.Sprintf("%s", cookie.Value))
}
