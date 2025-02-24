package middleware

import (
    "runtime/debug"
    "github.com/gofiber/fiber/v2"
    "go.uber.org/zap"
)

func RecoveryMiddleware(logger *zap.Logger) fiber.Handler {
    return func(c *fiber.Ctx) error {
        defer func() {
            if r := recover(); r != nil {
                stack := debug.Stack()
                logger.Error("panic recovered",
                    zap.Any("error", r),
                    zap.ByteString("stack", stack),
                    zap.String("path", c.Path()),
                    zap.String("method", c.Method()),
                )

                c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
                    "error": "An internal server error occurred",
                    "code":  "INTERNAL_SERVER_ERROR",
                })
            }
        }()
        return c.Next()
    }
}
