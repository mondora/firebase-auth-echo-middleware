# firebase-auth-echo-middleware [![Go Report Card](https://goreportcard.com/badge/github.com/mondora/firebase-auth-echo-middleware)](https://goreportcard.com/report/github.com/mondora/firebase-auth-echo-middleware)
define Golang firebase auth middleware for echo web framework https://echo.labstack.com/

# install
```shell script
go get github.com/mondora/firebase-auth-echo-middleware
```

# example
```go
package main

import (
	"github.com/labstack/echo/v4"
	firebaseauth "github.com/mondora/firebase-auth-echo-middleware"
)

type H map[string]interface{}

func testApiHandler(c echo.Context) error {
	user := c.Get("user")
	authProvider := c.Get("auth-provider")
	return c.JSON(200, H{
		"user": user,
		"authProvider": authProvider,
		"OK":      true,
	})
}

func optionsSkipper(c echo.Context) bool {
	return c.Request().Method == "OPTIONS"
}

func main() {
	credentialJSON := `{
	  "type": "service_account",
	  "project_id": "...",
	  "private_key_id": "...",
	  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n",
	  "client_email": "firebase-adminsdk-...@....iam.gserviceaccount.com",
	  "client_id": "...",
	  "auth_uri": "https://accounts.google.com/o/oauth2/auth",
	  "token_uri": "https://oauth2.googleapis.com/token",
	  "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
	  "client_x509_cert_url": "..."
	}`
	firebaseAuth := firebaseauth.WithConfig(firebaseauth.Config{
		Skipper:        optionsSkipper,
		CredentialJSON: []byte(credentialJSON),
	})
	router := echo.New()
	apiV1 := router.Group("/api/v1")
	apiV1.Use(firebaseAuth)
	apiV1.GET("/test-api", testApiHandler)
}
```