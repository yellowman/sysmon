/* The production build scans the templates for every class they use.
 * Rebuild static/app.css after changing classes: make css (web-ui/). */
module.exports = {
  content: ["./templates/*.html"],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['JetBrains Mono', 'ui-monospace', 'monospace'],
      },
    },
  },
};
