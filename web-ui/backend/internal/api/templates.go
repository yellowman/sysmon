package api

import (
	"html/template"
	"net/http"
	"path/filepath"
)

var templates *template.Template

// InitTemplates initializes HTML templates
func InitTemplates(templateDir string) error {
	var err error
	templates, err = template.ParseGlob(filepath.Join(templateDir, "*.html"))
	return err
}

// renderTemplate renders an HTML template
func (r *Router) renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	if templates == nil {
		http.Error(w, "Templates not loaded", http.StatusInternalServerError)
		return
	}

	err := templates.ExecuteTemplate(w, tmpl, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Page handlers
func (r *Router) handleDashboard(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "dashboard.html", nil)
}

func (r *Router) handleHostsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "hosts.html", nil)
}

func (r *Router) handleTrapsPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "traps.html", nil)
}

func (r *Router) handleConfigPage(w http.ResponseWriter, req *http.Request) {
	r.renderTemplate(w, "config.html", nil)
}
