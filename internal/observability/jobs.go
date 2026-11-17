package observability

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// jobInstruments are the background-job metrics. They are created lazily from
// the global MeterProvider, which forwards to whatever Setup installs.
var jobInstruments = sync.OnceValue(func() (j struct {
	runs        metric.Int64Counter
	duration    metric.Float64Histogram
	lastSuccess metric.Float64Gauge
}) {
	m := otel.Meter("github.com/xilasec/xila-api/internal/observability")
	// Errors only come from invalid names/units, which are constants here;
	// a failed instrument is a no-op, never a crash.
	j.runs, _ = m.Int64Counter("xila.job.runs",
		metric.WithDescription("Background job runs (sweeps, feed syncs), by job and outcome (ok, error, canceled)."))
	j.duration, _ = m.Float64Histogram("xila.job.duration", metric.WithUnit("s"),
		metric.WithDescription("Background job run duration."))
	j.lastSuccess, _ = m.Float64Gauge("xila.job.last_success", metric.WithUnit("s"),
		metric.WithDescription("Unix time of the job's last successful run; time() minus this is a feed's age."))
	return j
})

// RecordJob records one run of a background job (a sweep or a feed sync)
// that started at start and ended with err. Every scheduled job reports here,
// so one dashboard covers them all: run rate, failure rate, duration, and how
// long since each last succeeded.
func RecordJob(ctx context.Context, job string, start time.Time, err error) {
	j := jobInstruments()
	outcome := "ok"
	switch {
	case err == nil:
	case errors.Is(err, context.Canceled) || ctx.Err() != nil:
		outcome = "canceled" // shutdown or leadership loss, not a failure
	default:
		outcome = "error"
	}
	name := attribute.String("job", job)
	j.runs.Add(ctx, 1, metric.WithAttributes(name, attribute.String("outcome", outcome)))
	j.duration.Record(ctx, time.Since(start).Seconds(), metric.WithAttributes(name))
	if err == nil {
		j.lastSuccess.Record(ctx, float64(time.Now().Unix()), metric.WithAttributes(name))
	}
}

// GuardMetrics requires `Authorization: Bearer <token>` on the scrape
// endpoint when token() is non-empty (METRICS_TOKEN); empty = open. token is
// read fresh on every request (not just at startup), so a rotated
// METRICS_TOKEN (M10 10.2) takes effect without a restart in either
// direction — turned on, turned off, or changed.
func GuardMetrics(h http.Handler, token func() string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if t := token(); t != "" {
			want := []byte("Bearer " + t)
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), want) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
		}
		h.ServeHTTP(w, r)
	})
}
