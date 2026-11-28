// Package observability wires OpenTelemetry traces, metrics and logs, and
// installs a structured slog logger that fans out to stdout and OTLP.
package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	runtimemetrics "go.opentelemetry.io/contrib/instrumentation/runtime"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"

	"github.com/xilasec/xila-api/internal/config"
)

// ShutdownFunc flushes and releases all telemetry providers.
type ShutdownFunc func(context.Context) error

// Telemetry is what Setup installed.
type Telemetry struct {
	// Shutdown flushes and releases every provider; call it on exit.
	Shutdown ShutdownFunc
	// Metrics serves the Prometheus exposition of every OpenTelemetry
	// instrument (METRICS_ENABLED); nil when disabled.
	Metrics http.Handler
}

// Setup installs global OpenTelemetry providers and the default slog logger.
// Metrics have two optional readers on one MeterProvider — the OTLP push
// (OTEL_ENABLED) and the Prometheus pull (METRICS_ENABLED) — so every
// instrument reaches both, and /metrics works without a collector.
func Setup(ctx context.Context, cfg config.Config) (Telemetry, error) {
	if !cfg.Otel.Enabled {
		// Structured JSON logs on stdout still; metrics only if scraped.
		slog.SetDefault(slog.New(stdoutHandler()))
		slog.Info("opentelemetry disabled; logging to stdout only")
		if !cfg.Metrics.Enabled {
			return Telemetry{Shutdown: func(context.Context) error { return nil }}, nil
		}
		res, err := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(cfg.Otel.ServiceName)))
		if err != nil {
			return Telemetry{}, fmt.Errorf("build otel resource: %w", err)
		}
		reader, handler, err := prometheusReader()
		if err != nil {
			return Telemetry{}, err
		}
		mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader), sdkmetric.WithResource(res), boundedHTTPLabels)
		otel.SetMeterProvider(mp)
		if err := runtimemetrics.Start(runtimemetrics.WithMinimumReadMemStatsInterval(time.Second)); err != nil {
			return Telemetry{}, fmt.Errorf("start runtime metrics: %w", err)
		}
		return Telemetry{Shutdown: mp.Shutdown, Metrics: handler}, nil
	}

	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithTelemetrySDK(),
		resource.WithProcess(),
		resource.WithAttributes(
			semconv.ServiceName(cfg.Otel.ServiceName),
			attribute.String("deployment.environment", cfg.Env),
		),
	)
	if err != nil {
		return Telemetry{}, fmt.Errorf("build otel resource: %w", err)
	}

	var shutdowns []ShutdownFunc

	// Context propagation across service boundaries (W3C trace-context + baggage).
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	// ---- Traces ----
	traceExp, err := otlptracegrpc.New(ctx, traceOpts(cfg.Otel)...)
	if err != nil {
		return Telemetry{}, fmt.Errorf("create trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExp),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)
	shutdowns = append(shutdowns, tp.Shutdown)

	// ---- Metrics ----
	metricExp, err := otlpmetricgrpc.New(ctx, metricOpts(cfg.Otel)...)
	if err != nil {
		return Telemetry{}, fmt.Errorf("create metric exporter: %w", err)
	}
	readers := []sdkmetric.Option{
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(metricExp)),
		sdkmetric.WithResource(res),
		boundedHTTPLabels,
	}
	var metricsHandler http.Handler
	if cfg.Metrics.Enabled {
		reader, handler, err := prometheusReader()
		if err != nil {
			return Telemetry{}, err
		}
		readers = append(readers, sdkmetric.WithReader(reader))
		metricsHandler = handler
	}
	mp := sdkmetric.NewMeterProvider(readers...)
	otel.SetMeterProvider(mp)
	shutdowns = append(shutdowns, mp.Shutdown)

	// Collect Go runtime metrics (GC, goroutines, memory) out of the box.
	if err := runtimemetrics.Start(runtimemetrics.WithMinimumReadMemStatsInterval(time.Second)); err != nil {
		return Telemetry{}, fmt.Errorf("start runtime metrics: %w", err)
	}

	// ---- Logs ----
	logExp, err := otlploggrpc.New(ctx, logOpts(cfg.Otel)...)
	if err != nil {
		return Telemetry{}, fmt.Errorf("create log exporter: %w", err)
	}
	lp := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(logExp)),
		sdklog.WithResource(res),
	)
	otel.SetLoggerProvider(lp)
	shutdowns = append(shutdowns, lp.Shutdown)

	// slog -> (stdout JSON + OTLP logs). The OTel bridge automatically
	// correlates each record with the active trace/span.
	logger := slog.New(newFanoutHandler(
		stdoutHandler(),
		otelslog.NewHandler(cfg.Otel.ServiceName, otelslog.WithLoggerProvider(lp)),
	))
	slog.SetDefault(logger)

	return Telemetry{Metrics: metricsHandler, Shutdown: func(ctx context.Context) error {
		var err error
		// Shut down in reverse order of registration.
		for _, shutdown := range slices.Backward(shutdowns) {
			err = errors.Join(err, shutdown(ctx))
		}
		return err
	}}, nil
}

// boundedHTTPLabels drops server.address from the HTTP server metrics: the
// middleware fills it from the client's Host header, so anyone could mint a
// new time series per request. Routes are already templates (/projects/:id).
var boundedHTTPLabels = sdkmetric.WithView(sdkmetric.NewView(
	sdkmetric.Instrument{Scope: instrumentation.Scope{Name: "github.com/gofiber/contrib/otelfiber"}},
	sdkmetric.Stream{AttributeFilter: attribute.NewDenyKeysFilter(semconv.ServerAddressKey)},
))

// prometheusReader is a metric reader that serves the Prometheus text format
// from its own registry (not the global one: nothing else registers there).
func prometheusReader() (sdkmetric.Reader, http.Handler, error) {
	reg := prometheus.NewRegistry()
	exp, err := otelprom.New(otelprom.WithRegisterer(reg))
	if err != nil {
		return nil, nil, fmt.Errorf("create prometheus exporter: %w", err)
	}
	return exp, promhttp.HandlerFor(reg, promhttp.HandlerOpts{}), nil
}

func stdoutHandler() slog.Handler {
	return slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})
}

func traceOpts(c config.Otel) []otlptracegrpc.Option {
	opts := []otlptracegrpc.Option{otlptracegrpc.WithEndpoint(c.Endpoint)}
	if c.Insecure {
		opts = append(opts, otlptracegrpc.WithInsecure())
	}
	return opts
}

func metricOpts(c config.Otel) []otlpmetricgrpc.Option {
	opts := []otlpmetricgrpc.Option{otlpmetricgrpc.WithEndpoint(c.Endpoint)}
	if c.Insecure {
		opts = append(opts, otlpmetricgrpc.WithInsecure())
	}
	return opts
}

func logOpts(c config.Otel) []otlploggrpc.Option {
	opts := []otlploggrpc.Option{otlploggrpc.WithEndpoint(c.Endpoint)}
	if c.Insecure {
		opts = append(opts, otlploggrpc.WithInsecure())
	}
	return opts
}
