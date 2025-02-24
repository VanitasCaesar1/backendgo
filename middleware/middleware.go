package middleware

import (
	"strings"

	"github.com/Nerzal/gocloak/v13"
	"github.com/gofiber/fiber/v2"
)

type KeycloakMiddleware struct {
	client *gocloak.GoCloak
	realm  string
}

func NewKeycloakMiddleware(serverURL, realm string) *KeycloakMiddleware {
	return &KeycloakMiddleware{
		client: gocloak.NewClient(serverURL),
		realm:  realm,
	}
}

func (k *KeycloakMiddleware) AuthMiddleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "No authorization header",
			})
		}

		bearerToken := strings.Replace(authHeader, "Bearer ", "", 1)

		token, claims, err := k.client.DecodeAccessToken(c.Context(), bearerToken, k.realm)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error": "Invalid Token",
			})
		}

		c.Locals("token", token)
		c.Locals("claims", claims)

		return c.Next()
	}

}
