package main

import (
	"github.com/binhatch/go-turnstile/echoturnstile"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
)

const (
	invalidSecret = "2x0000000000000000000000000000000AA"
	validSecret   = "1x0000000000000000000000000000000AA"
)

func main() {
	e := echo.New()

	e.GET("/", func(c echo.Context) error {
		return c.NoContent(204)
	})

	e.Use(middleware.Logger())
	e.Use(echoturnstile.NewMiddleware(invalidSecret))
	e.Start(":5432")
}
