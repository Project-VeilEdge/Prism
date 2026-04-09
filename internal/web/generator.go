// Package web implements the camouflage web page generator and HTTP handler.
// Pages are generated at startup from embedded templates and cached in memory.
package web

import (
	"bytes"
	"html/template"
	"math/rand"
)

// Page is a pre-rendered HTTP response body.
type Page struct {
	Body        []byte
	ContentType string
	StatusCode  int
}

// Generator builds HTML pages at startup based on theme and seed,
// then caches them in memory for zero-IO serving.
type Generator struct {
	seed     int64
	siteName string
	pages    map[string]*Page
}

var siteNames = []string{
	"Oakfield Solutions", "Clearwater Digital", "Summit Advisory",
	"Lakeview Consulting", "Greenleaf Partners", "Bridgepoint Corp",
	"Westgate Services", "Pinecrest Holdings", "Bayshore Group",
	"Ridgeline Analytics",
}

var taglines = []string{
	"Professional services for growing businesses.",
	"Trusted partners in digital transformation.",
	"Simple solutions for complex challenges.",
	"Helping teams work smarter, not harder.",
	"Your success is our priority.",
}

var aboutTexts = []string{
	"We are a small team dedicated to delivering quality results.",
	"Founded in 2019, we serve clients across multiple industries.",
	"Our expertise spans technology, strategy, and operations.",
	"We believe in transparency, reliability, and long-term partnerships.",
}

var contactTexts = []string{
	"Reach out to us at info@example.com for inquiries.",
	"We would love to hear from you. Send us a message any time.",
	"For business inquiries, please use the contact form on our main site.",
	"Get in touch — we typically respond within one business day.",
}

// NewGenerator creates a Generator that pre-renders all pages.
// If seed is 0, a non-deterministic random source is used.
// Only the "minimal" theme is implemented; the theme parameter is accepted
// for forward compatibility but currently ignored.
func NewGenerator(theme string, seed int64, siteName string) *Generator {
	g := &Generator{
		seed:     seed,
		siteName: siteName,
		pages:    make(map[string]*Page),
	}
	g.generate()
	return g
}

func (g *Generator) generate() {
	var rng *rand.Rand
	if g.seed != 0 {
		rng = rand.New(rand.NewSource(g.seed))
	} else {
		rng = rand.New(rand.NewSource(rand.Int63()))
	}

	siteName := g.siteName
	if siteName == "" {
		siteName = siteNames[rng.Intn(len(siteNames))]
	}

	data := map[string]string{
		"SiteName":    siteName,
		"Tagline":     taglines[rng.Intn(len(taglines))],
		"AboutText":   aboutTexts[rng.Intn(len(aboutTexts))],
		"ContactText": contactTexts[rng.Intn(len(contactTexts))],
	}

	// Resolve theme directory — only "minimal" is supported.
	themeDir := "minimal"

	g.pages["/"] = g.renderTemplate(themeDir+"/index.html", data, 200)
	g.pages["/about"] = g.renderTemplate(themeDir+"/about.html", data, 200)
	g.pages["/contact"] = g.renderTemplate(themeDir+"/contact.html", data, 200)
	g.pages["404"] = g.renderTemplate(themeDir+"/404.html", data, 404)

	// Static files loaded directly from embed.
	robotsTxt, _ := templateFS.ReadFile("templates/robots.txt")
	g.pages["/robots.txt"] = &Page{Body: robotsTxt, ContentType: "text/plain; charset=utf-8", StatusCode: 200}

	faviconData, _ := templateFS.ReadFile("templates/favicon.ico")
	g.pages["/favicon.ico"] = &Page{Body: faviconData, ContentType: "image/x-icon", StatusCode: 200}
}

func (g *Generator) renderTemplate(name string, data map[string]string, status int) *Page {
	raw, err := templateFS.ReadFile("templates/" + name)
	if err != nil {
		return &Page{Body: []byte("Internal Error"), ContentType: "text/plain", StatusCode: 500}
	}
	tmpl, err := template.New(name).Parse(string(raw))
	if err != nil {
		return &Page{Body: []byte("Internal Error"), ContentType: "text/plain", StatusCode: 500}
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return &Page{Body: []byte("Internal Error"), ContentType: "text/plain", StatusCode: 500}
	}
	return &Page{Body: buf.Bytes(), ContentType: "text/html; charset=utf-8", StatusCode: status}
}
