package traefik_header_auth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
)

type HeaderRule struct {
	Name    string
	Pattern string
}

type Config struct {
	Headers []HeaderRule `json:"headers,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Headers: make([]HeaderRule, 0),
	}
}

type HeaderAuth struct {
	next    http.Handler
	headers []HeaderRule
	name    string
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.Headers) == 0 {
		return nil, fmt.Errorf("headers cannot be empty")
	}

	return &HeaderAuth{
		headers: config.Headers,
		next:    next,
		name:    name,
	}, nil
}

func (plugin *HeaderAuth) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	for _, rule := range plugin.headers {
		// catch empty entries
		if rule.Name == "" || rule.Pattern == "" {
			continue
		}

		headerValue := req.Header.Get(rule.Name)
		os.Stdout.WriteString(fmt.Sprintf("%s: %s\n", rule.Name, headerValue))
		if headerValue == "" {
			http.Error(rw, "missing header", http.StatusBadRequest)
			os.Stdout.WriteString(fmt.Sprintf("header '%s' not provided in request\n", rule.Name))
			return
		}

		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			http.Error(rw, "configuration error", http.StatusInternalServerError)
			os.Stdout.WriteString(fmt.Sprintf("regex pattern for header '%s' does not compile\n", rule.Name))
			return
		}

		match := re.MatchString(headerValue)
		if !match {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			os.Stdout.WriteString(fmt.Sprintf("value for header '%s' does not match regular expression\n", rule.Name))
			return
		}
	}

	plugin.next.ServeHTTP(rw, req)
}
