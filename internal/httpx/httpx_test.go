package httpx

import (
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
)

// An id must outlive its request: handlers hand it to goroutines
// (notifications, issue-tracker pushes). Fiber's Params point into a buffer
// it reuses for the next request, so an uncopied id silently changes.
func TestIDOutlivesRequest(t *testing.T) {
	app := fiber.New()
	var got []string
	app.Get("/x/:id", func(c *fiber.Ctx) error {
		id, err := ID(c, "id")
		if err != nil {
			return err
		}
		got = append(got, id)
		return nil
	})
	var want []string
	for range 100 {
		id := uuid.NewString()
		want = append(want, id)
		if _, err := app.Test(httptest.NewRequest(fiber.MethodGet, "/x/"+id, nil), -1); err != nil {
			t.Fatal(err)
		}
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("request %d's id changed after the request ended: %s, want %s", i, got[i], want[i])
		}
	}
}
