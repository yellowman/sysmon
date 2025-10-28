package api

import (
	"bytes"
	"html/template"
	"log"
	"net/http"
	"path/filepath"
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
		// At this point headers are already sent, but log the write error
		log.Printf("Error writing template output for %s: %v", tmpl, err)
	}
}

// Page handlers
func (r *Router) handleDashboard(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "dashboard.html", nil)
}

func (r *Router) handleHostsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "hosts.html", nil)
}

func (r *Router) handleHostDetailPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "hosts-detail.html", nil)
}

func (r *Router) handleTrapsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "traps.html", nil)
}

func (r *Router) handleConfigPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "config.html", nil)
}

func (r *Router) handleAdminPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "admin.html", nil)
}

func (r *Router) handleMetricsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "metrics.html", nil)
}
