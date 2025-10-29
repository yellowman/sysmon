package api

import (
	"bytes"
	"errors"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
	"syscall"
)

var templateCache map[string]*template.Template
var templateDir string

// InitTemplates initializes HTML templates
func InitTemplates(dir string) error {
	templateDir = dir
	templateCache = make(map[string]*template.Template)

	// List of page templates to load
	pages := []string{
		"dashboard.html",
		"hosts.html",
		"hosts-detail.html",
		"traps.html",
		"config.html",
		"admin.html",
		"metrics.html",
	}

	// Parse each page template along with base template
	for _, page := range pages {
		tmpl, err := template.ParseFiles(
			filepath.Join(templateDir, "base.html"),
			filepath.Join(templateDir, page),
		)
		if err != nil {
			return err
		}
		templateCache[page] = tmpl
	}

	return nil
}

// renderTemplate renders an HTML template
func (r *Router) renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	t, ok := templateCache[tmpl]
	if !ok {
		http.Error(w, "Template not found: "+tmpl, http.StatusInternalServerError)
		return
	}

	// Render to buffer first to catch errors before writing to response
	// This prevents sending a 200 OK status when template execution fails
	var buf bytes.Buffer
	err := t.ExecuteTemplate(&buf, "base", data)
	if err != nil {
		log.Printf("Error executing template %s: %v", tmpl, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Only write to response if template executed successfully
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Prevent browser caching to ensure fresh content on every load
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	_, err = buf.WriteTo(w)
	if err != nil {
		// Check if this is a broken pipe error (client disconnected)
		// These are normal and shouldn't be logged as errors
		if isBrokenPipe(err) {
			// Client disconnected - this is expected, don't log
			return
		}
		// For other write errors, log them
		log.Printf("Error writing template output for %s: %v", tmpl, err)
	}
}

// isBrokenPipe checks if an error is a broken pipe error (client disconnect)
func isBrokenPipe(err error) bool {
	// Check for EPIPE (broken pipe) or ECONNRESET (connection reset by peer)
	var syscallErr syscall.Errno
	if errors.As(err, &syscallErr) {
		return syscallErr == syscall.EPIPE || syscallErr == syscall.ECONNRESET
	}
	return false
}

// PageData contains template data for page rendering
type PageData struct {
	Active   string // Current active page for navigation highlighting
	Hostname string // Hostname for host detail pages
}

// Page handlers
func (r *Router) handleDashboard(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "dashboard.html", PageData{Active: "dashboard"})
}

func (r *Router) handleHostsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "hosts.html", PageData{Active: "hosts"})
}

func (r *Router) handleHostDetailPage(w http.ResponseWriter, req *http.Request) {
	// Extract hostname from query parameter
	hostname := req.URL.Query().Get("hostname")
	
	r.renderTemplate(w, "hosts-detail.html", PageData{
		Active:   "hosts",
		Hostname: hostname,
	})
}

func (r *Router) handleTrapsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "traps.html", PageData{Active: "traps"})
}

func (r *Router) handleConfigPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "config.html", PageData{Active: "config"})
}

func (r *Router) handleAdminPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "admin.html", PageData{Active: "admin"})
}

func (r *Router) handleMetricsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "metrics.html", PageData{Active: "metrics"})
}
