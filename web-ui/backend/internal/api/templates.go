package api

import (
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

	// Execute the base template which includes the page-specific content
	// Note: If ExecuteTemplate returns an error, it may have already started writing
	// to the response, so we can't call http.Error (which would cause a superfluous
	// WriteHeader call). We just log the error instead.
	err := t.ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Printf("Error executing template %s: %v", tmpl, err)
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
