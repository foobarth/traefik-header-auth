package headerAuth

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"regexp"
)

type Config struct {
	Headers map[string]string `json:"headers,omitempty"`
}

func CreateConfig() *Config {
	return &Config{
		Headers: make(map[string]string),
	}
}

type HeaderAuth struct {
	next    http.Handler
	headers map[string]string
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
	for key, value := range plugin.headers {
		headerValue := req.Header.Get(key)
		if headerValue == "" {
			http.Error(rw, "missing header", http.StatusBadRequest)
			os.Stderr.WriteString(fmt.Sprintf("header '%s' not provided in request", key))
			return
		}

		re, err := regexp.Compile(value)
		if err != nil {
			http.Error(rw, "configuration error", http.StatusInternalServerError)
			os.Stderr.WriteString(fmt.Sprintf("regex pattern for header '%s' does not compile", key))
			return
		}

		match := re.MatchString(headerValue)
		if !match {
			http.Error(rw, "unauthorized", http.StatusUnauthorized)
			os.Stderr.WriteString(fmt.Sprintf("value for header '%s' does not match regular expression", key))
			return
		}
	}

	plugin.next.ServeHTTP(rw, req)
}
