package headerAuth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	headerAuth "github.com/foobarth/traefik-header-auth"
)

func TestHeaderAuth(t *testing.T) {
	cfg := headerAuth.CreateConfig()
	cfg.Headers["User-Agent"] = ":* myAllowedUserAgent .*"

	ctx := context.Background()
	next := http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {})

	handler, err := headerAuth.New(ctx, next, cfg, "headerAuth-plugin")
	if err != nil {
		t.Fatal(err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost", nil)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("User-Agent", "I am myAllowedUserAgent and therefore should be okay")
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assertStatus(t, recorder.Result(), http.StatusOK)

	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assertStatus(t, recorder.Result(), http.StatusUnauthorized)

	req.Header.Del("User-Agent")
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, req)
	assertStatus(t, recorder.Result(), http.StatusBadRequest)
}

func assertStatus(t *testing.T, rsp *http.Response, expected int) {
	t.Helper()

	if rsp.StatusCode != expected {
		t.Errorf("invalid response status code: %d", rsp.StatusCode)
	}
}
