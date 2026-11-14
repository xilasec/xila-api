// Package httpx holds small helpers shared by HTTP handlers.
package httpx

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// DefaultLimit and MaxLimit bound list pagination.
const (
	DefaultLimit = 50
	MaxLimit     = 200
)

// Page holds a parsed limit/offset window.
type Page struct {
	Limit  int
	Offset int
}

// ParsePage reads ?limit= and ?offset=, applying defaults and caps.
func ParsePage(c *fiber.Ctx) Page {
	limit, _ := strconv.Atoi(c.Query("limit"))
	if limit <= 0 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	offset, _ := strconv.Atoi(c.Query("offset"))
	if offset < 0 {
		offset = 0
	}
	return Page{Limit: limit, Offset: offset}
}

// Meta is the pagination envelope returned alongside list results.
func Meta(p Page, count int, hasMore bool) fiber.Map {
	return fiber.Map{
		"limit":    p.Limit,
		"offset":   p.Offset,
		"count":    count,
		"has_more": hasMore,
	}
}

// ID reads a UUID path parameter, returning a 400 fiber error when malformed.
func ID(c *fiber.Ctx, name string) (string, error) {
	raw := c.Params(name)
	if _, err := uuid.Parse(raw); err != nil {
		return "", fiber.NewError(fiber.StatusBadRequest, "invalid "+name)
	}
	return raw, nil
}

// Parse decodes the JSON request body into dst, returning a 400 on failure.
func Parse(c *fiber.Ctx, dst any) error {
	if err := c.BodyParser(dst); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "invalid request body")
	}
	return nil
}
