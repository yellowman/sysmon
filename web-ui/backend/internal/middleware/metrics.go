package middleware

import (
	"net/http"
	"sync"
	"time"
)

// MetricsCollector tracks API usage statistics
type MetricsCollector struct {
	mu sync.RWMutex

	// Overall statistics
	totalRequests     int64
	successfulRequests int64
	failedRequests    int64
	totalBytes        int64

	// Per-endpoint statistics
	endpointStats map[string]*EndpointStats

	// Rate limiting statistics
	rateLimitHits int64

	// Bulk operation statistics
	bulkOperations     int64
	bulkHostsProcessed int64

	// Time-based windows (last hour, last day)
	requestsLastHour  []TimePoint
	requestsLastDay   []TimePoint
	startTime         time.Time
}

// EndpointStats tracks statistics for a specific endpoint
type EndpointStats struct {
	Path         string
	TotalCalls   int64
	SuccessCalls int64
	FailedCalls  int64
	AvgDuration  float64
	totalDuration time.Duration
}

// TimePoint represents a data point in time
type TimePoint struct {
	Timestamp time.Time
	Count     int64
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector() *MetricsCollector {
	mc := &MetricsCollector{
		endpointStats:    make(map[string]*EndpointStats),
		requestsLastHour: make([]TimePoint, 0),
		requestsLastDay:  make([]TimePoint, 0),
		startTime:        time.Now(),
	}

	// Start cleanup goroutine
	go mc.cleanupOldMetrics()

	return mc
}

// Middleware wraps an HTTP handler with metrics collection
func (mc *MetricsCollector) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap the response writer to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Call the next handler
		next.ServeHTTP(rw, r)

		// Record metrics
		duration := time.Since(start)
		mc.RecordRequest(r.URL.Path, rw.statusCode, duration)
	})
}

// RecordRequest records a single API request
func (mc *MetricsCollector) RecordRequest(path string, statusCode int, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.totalRequests++

	if statusCode >= 200 && statusCode < 400 {
		mc.successfulRequests++
	} else {
		mc.failedRequests++
	}

	// Update endpoint stats
	if _, exists := mc.endpointStats[path]; !exists {
		mc.endpointStats[path] = &EndpointStats{Path: path}
	}

	stats := mc.endpointStats[path]
	stats.TotalCalls++
	stats.totalDuration += duration

	if statusCode >= 200 && statusCode < 400 {
		stats.SuccessCalls++
	} else {
		stats.FailedCalls++
	}

	stats.AvgDuration = float64(stats.totalDuration.Milliseconds()) / float64(stats.TotalCalls)

	// Record time point
	now := time.Now()
	mc.requestsLastHour = append(mc.requestsLastHour, TimePoint{Timestamp: now, Count: 1})
	mc.requestsLastDay = append(mc.requestsLastDay, TimePoint{Timestamp: now, Count: 1})
}

// RecordRateLimitHit records a rate limit hit
func (mc *MetricsCollector) RecordRateLimitHit() {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.rateLimitHits++
}

// RecordBulkOperation records a bulk operation
func (mc *MetricsCollector) RecordBulkOperation(hostsCount int) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.bulkOperations++
	mc.bulkHostsProcessed += int64(hostsCount)
}

// GetMetrics returns current metrics
func (mc *MetricsCollector) GetMetrics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	uptime := time.Since(mc.startTime)

	// Calculate requests per second
	requestsPerSecond := float64(mc.totalRequests) / uptime.Seconds()

	// Get top endpoints
	topEndpoints := make([]map[string]interface{}, 0)
	for _, stats := range mc.endpointStats {
		topEndpoints = append(topEndpoints, map[string]interface{}{
			"path":         stats.Path,
			"total_calls":  stats.TotalCalls,
			"success":      stats.SuccessCalls,
			"failed":       stats.FailedCalls,
			"avg_duration": stats.AvgDuration,
		})
	}

	// Sort by total calls (simple bubble sort for small datasets)
	for i := 0; i < len(topEndpoints); i++ {
		for j := i + 1; j < len(topEndpoints); j++ {
			if topEndpoints[j]["total_calls"].(int64) > topEndpoints[i]["total_calls"].(int64) {
				topEndpoints[i], topEndpoints[j] = topEndpoints[j], topEndpoints[i]
			}
		}
	}

	// Limit to top 20
	if len(topEndpoints) > 20 {
		topEndpoints = topEndpoints[:20]
	}

	// Calculate time-based metrics
	now := time.Now()
	requestsLastMinute := int64(0)
	requestsLastHourCount := int64(0)

	for _, tp := range mc.requestsLastHour {
		if now.Sub(tp.Timestamp) < time.Minute {
			requestsLastMinute += tp.Count
		}
		requestsLastHourCount += tp.Count
	}

	return map[string]interface{}{
		"uptime_seconds":       int64(uptime.Seconds()),
		"total_requests":       mc.totalRequests,
		"successful_requests":  mc.successfulRequests,
		"failed_requests":      mc.failedRequests,
		"requests_per_second":  requestsPerSecond,
		"requests_last_minute": requestsLastMinute,
		"requests_last_hour":   requestsLastHourCount,
		"rate_limit_hits":      mc.rateLimitHits,
		"bulk_operations":      mc.bulkOperations,
		"bulk_hosts_processed": mc.bulkHostsProcessed,
		"top_endpoints":        topEndpoints,
	}
}

// cleanupOldMetrics removes old time points
func (mc *MetricsCollector) cleanupOldMetrics() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		mc.mu.Lock()

		now := time.Now()

		// Clean up hour window
		hourAgo := now.Add(-time.Hour)
		newHourData := make([]TimePoint, 0)
		for _, tp := range mc.requestsLastHour {
			if tp.Timestamp.After(hourAgo) {
				newHourData = append(newHourData, tp)
			}
		}
		mc.requestsLastHour = newHourData

		// Clean up day window
		dayAgo := now.Add(-24 * time.Hour)
		newDayData := make([]TimePoint, 0)
		for _, tp := range mc.requestsLastDay {
			if tp.Timestamp.After(dayAgo) {
				newDayData = append(newDayData, tp)
			}
		}
		mc.requestsLastDay = newDayData

		mc.mu.Unlock()
	}
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}
