package server

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// A request that fails is logged with the status the client got — not the 200
// the response held before the error handler ran. (Denials and failures were
// invisible in the request log.)
func TestRequestLogRecordsErrorStatus(t *testing.T) {
	var buf bytes.Buffer
	prev := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&buf, nil)))
	t.Cleanup(func() { slog.SetDefault(prev) })

	app := fiber.New(fiber.Config{ErrorHandler: errorHandler})
	app.Use(requestLogger())
	app.Get("/denied", func(*fiber.Ctx) error { return fiber.NewError(fiber.StatusForbidden, "no") })
	app.Get("/ok", func(c *fiber.Ctx) error { return c.SendString("ok") })

	for path, want := range map[string]int{"/denied": 403, "/ok": 200} {
		buf.Reset()
		resp, err := app.Test(httptest.NewRequest(http.MethodGet, path, nil))
		if err != nil {
			t.Fatal(err)
		}
		var line struct {
			Status int `json:"status"`
		}
		if err := json.Unmarshal(buf.Bytes(), &line); err != nil {
			t.Fatalf("%s: log line %q: %v", path, buf.String(), err)
		}
		if resp.StatusCode != want || line.Status != want {
			t.Errorf("%s: client got %d, log says %d; want %d", path, resp.StatusCode, line.Status, want)
		}
	}
}
