package firebaseauth

import (
	"context"
	"encoding/json"
	firebase "firebase.google.com/go/v4"
	"fmt"
	"google.golang.org/api/option"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

/**
Google Firebase AUTH - echo middleware definition
*/

type (
	// Config defines the config for Firebase Auth JWT middleware.
	Config struct {
		// Skipper defines a function to skip middleware.
		Skipper middleware.Skipper

		// ID key to store user information from the token into context.
		// Optional. Default value "id-key".
		ContextIDKey string

		// Context key to store user information from the user into context.
		// Optional. Default value "user".
		ContextUserKey string

		// Claims are extendable claims data defining token content.
		// Optional. Default value gwt.MapClaims
		//Claims gwt.ClaimSet

		// TokenLookup is a string in the form of "<source>:<name>" that is used
		// to extract token from the request.
		// Optional. Default value "header:Authorization".
		// Possible values:
		// - "header:<name>"
		// - "query:<name>"
		// - "cookie:<name>"
		TokenLookup string

		// AuthScheme to be used in the Authorization header.
		// Optional. Default value "Bearer".
		AuthScheme string

		CredentialJSON []byte
	}

	tokenExtractorFunc func(echo.Context) (string, error)
)

// Errors
var (
	ErrTokenMissing = echo.NewHTTPError(http.StatusBadRequest, "Missing or malformed Firebase AuthID TOKEN")
	ErrTokenInvalid = echo.NewHTTPError(http.StatusUnauthorized, "Invalid or expired Firebase AuthID TOKEN")
)

var (
	// nolint
	// DefaultFirebaseAuthConfig is the default auth middleware config.
	DefaultFirebaseAuthConfig = Config{
		Skipper:        middleware.DefaultSkipper,
		ContextIDKey:   "id-key",
		ContextUserKey: "user",
		TokenLookup:    "header:" + echo.HeaderAuthorization,
		AuthScheme:     "Bearer",
	}
)

// FirebaseAuth returns a JSON Web Token (JWT) auth middleware.
//
// For valid token, it sets the user in context and calls next handler.
// For invalid token, it returns "401 - Unauthorized" error.
// For missing token, it returns "400 - Bad Request" error.
func FirebaseAuth() echo.MiddlewareFunc {
	c := DefaultFirebaseAuthConfig
	return WithConfig(c)
}

// WithConfig returns a FirebaseAuth middleware with config.
// See: `FirebaseAuth()`.
func WithConfig(config Config) echo.MiddlewareFunc {
	// Defaults
	if config.Skipper == nil {
		config.Skipper = DefaultFirebaseAuthConfig.Skipper
	}
	if config.ContextUserKey == "" {
		config.ContextUserKey = DefaultFirebaseAuthConfig.ContextUserKey
	}
	if config.TokenLookup == "" {
		config.TokenLookup = DefaultFirebaseAuthConfig.TokenLookup
	}
	if config.AuthScheme == "" {
		config.AuthScheme = DefaultFirebaseAuthConfig.AuthScheme
	}

	// Initialize
	parts := strings.Split(config.TokenLookup, ":")
	extractor := tokenFromHeader(parts[1], config.AuthScheme)
	switch parts[0] {
	case "query":
		extractor = tokenFromQuery(parts[1])
	case "cookie":
		extractor = tokenFromCookie(parts[1])
	}

	if len(config.CredentialJSON) == 0 {
		panic("echo: FirebaseAuth middleware requires CredentialJSON")
	}
	authApp, err := firebase.NewApp(
		context.Background(),
		nil,
		option.WithCredentialsJSON(config.CredentialJSON))
	if err != nil {
		panic(fmt.Errorf("error initializing app: %v", err))
	}
	// Access auth service from the default app
	client, err := authApp.Auth(context.Background())
	if err != nil {
		panic(fmt.Errorf("error getting Auth client: %v", err))
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			if config.Skipper(c) {
				return next(c)
			}

			auth, err := extractor(c)
			if err != nil {
				return err
			}

			client.GetUser(context.Background(), auth)
			tok, err := client.VerifyIDToken(context.Background(), auth)
			if err != nil {
				return &echo.HTTPError{
					Code:     ErrTokenInvalid.Code,
					Message:  ErrTokenInvalid.Message,
					Internal: err,
				}
			}
			// Store user information from token into context.
			jsTok, _ := json.Marshal(tok)
			c.Set(config.ContextIDKey, string(jsTok))
			c.Set("auth-provider", "firebase")
			//return next(c)
			wantUser := c.Request().Header.Get("X-GetUser")
			if wantUser == "true" {
				user, err := client.GetUser(context.Background(), tok.UID)
				if err != nil {
					return &echo.HTTPError{
						Code:     ErrTokenInvalid.Code,
						Message:  ErrTokenInvalid.Message,
						Internal: err,
					}
				}
				jsUser, _ := json.Marshal(user)
				c.Set(config.ContextUserKey, string(jsUser))
			}
			return next(c)
			/*
			return &echo.HTTPError{
				Code:     ErrTokenInvalid.Code,
				Message:  ErrTokenInvalid.Message,
				Internal: err,
			}
			 */
		}
	}
}

// tokenFromHeader returns a `tokenExtractorFunc` that extracts token from the request header.
func tokenFromHeader(header string, authScheme string) tokenExtractorFunc {
	return func(c echo.Context) (string, error) {
		auth := c.Request().Header.Get(header)
		l := len(authScheme)
		if len(auth) > l+1 && auth[:l] == authScheme {
			return auth[l+1:], nil
		}
		return "", ErrTokenMissing
	}
}

// tokenFromQuery returns a `tokenExtractorFunc` that extracts token from the query string.
func tokenFromQuery(param string) tokenExtractorFunc {
	return func(c echo.Context) (string, error) {
		token := c.QueryParam(param)
		if token == "" {
			return "", ErrTokenMissing
		}
		return token, nil
	}
}

// tokenFromCookie returns a `tokenExtractorFunc` that extracts token from the named cookie.
func tokenFromCookie(name string) tokenExtractorFunc {
	return func(c echo.Context) (string, error) {
		cookie, err := c.Cookie(name)
		if err != nil {
			return "", ErrTokenMissing
		}
		return cookie.Value, nil
	}
}
