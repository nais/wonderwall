package templates

import (
	_ "embed"
	"html/template"
)

//go:embed output.css
var CSS template.CSS
