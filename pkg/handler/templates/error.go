package templates

import (
	_ "embed"
	"html/template"

	log "github.com/sirupsen/logrus"
)

//go:embed error.gohtml
var errorGoHtml string
var ErrorTemplate *template.Template

func init() {
	var err error

	ErrorTemplate = template.New("error")
	ErrorTemplate, err = ErrorTemplate.Parse(errorGoHtml)
	if err != nil {
		log.Fatalf("parsing error template: %+v", err)
	}
}
