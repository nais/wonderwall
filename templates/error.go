package templates

import (
	_ "embed"
	"html/template"
	"io"

	log "github.com/sirupsen/logrus"
)

//go:embed error.gohtml
var errorGoHtml string
var errorTemplate *template.Template

type ErrorVariables struct {
	CorrelationID      string
	CSS                template.CSS
	DefaultRedirectURI string
	HttpStatusCode     int
	RetryURI           string
}

func init() {
	var err error

	errorTemplate = template.New("error")
	errorTemplate, err = errorTemplate.Parse(errorGoHtml)
	if err != nil {
		log.Fatalf("parsing error template: %+v", err)
	}
}

func ExecError(w io.Writer, vars ErrorVariables) error {
	return errorTemplate.Execute(w, vars)
}
