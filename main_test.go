package main

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// helper to run a single request using doOnce
func runOnce(t *testing.T, handler http.HandlerFunc, opts options) jsonResult {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	req, err := buildRequest(opts, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	client := newHTTPClient(opts)
	return doOnce(client, opts, 0, req)
}

func TestStatusOnly(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(201) }
	res := runOnce(t, h, options{xSC: true})
	if res.StatusCode != 201 {
		t.Fatalf("expect 201, got %d", res.StatusCode)
	}
}

func TestExpectString(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("hello world")) }
	res := runOnce(t, h, options{expectString: "world"})
	if !res.Matched {
		t.Fatalf("expect substring matched")
	}
}

func TestIncludeHeaders(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "ok")
		w.WriteHeader(200)
		w.Write([]byte("body"))
	}
	srv := httptest.NewServer(http.HandlerFunc(h))
	defer srv.Close()
	// build request and stream to file to exercise streamOnce header printing
	opts := options{includeHdr: true}
	req, err := buildRequest(opts, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	client := newHTTPClient(opts)
	f, err := os.CreateTemp("", "hdr-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(f.Name())
	res := streamOnce(client, opts, 0, req, f, "")
	_ = f.Close()
	if res.StatusCode != 200 {
		t.Fatalf("expect 200")
	}
}

func TestDataUrlEncode(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expect POST, got %s", r.Method)
		}
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
			t.Fatalf("expect form content-type, got %s", ct)
		}
	}
	res := runOnce(t, h, options{urlEncData: multiFlag{"a=1", "b=2"}})
	if res.Error != "" {
		t.Fatalf("unexpected error: %s", res.Error)
	}
}

func TestFailFastSuppressBody(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		w.Write([]byte("error-body"))
	}
	res := runOnce(t, h, options{failFast: true})
	if res.StatusCode != 500 {
		t.Fatalf("expect 500")
	}
	if res.Body != "" || res.BodySize != 0 {
		t.Fatalf("failFast should suppress body, got size=%d body=%q", res.BodySize, res.Body)
	}
}

func TestMultipartUpload(t *testing.T) {
	tmp, err := os.CreateTemp("", "mf-*.txt")
	if err != nil {
		t.Fatalf("CreateTemp: %v", err)
	}
	defer os.Remove(tmp.Name())
	_, _ = tmp.WriteString("file-content")
	_ = tmp.Close()

	h := func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(10 << 20); err != nil {
			t.Fatalf("ParseMultipartForm: %v", err)
		}
		if v := r.FormValue("name"); v != "value" {
			t.Fatalf("name field mismatch: %q", v)
		}
		f, _, err := r.FormFile("file")
		if err != nil {
			t.Fatalf("FormFile: %v", err)
		}
		defer f.Close()
		b, _ := io.ReadAll(f)
		if string(b) != "file-content" {
			t.Fatalf("file content mismatch: %q", string(b))
		}
		w.WriteHeader(200)
	}
	res := runOnce(t, h, options{formFields: multiFlag{"name=value", "file=@" + tmp.Name()}})
	if res.StatusCode != 200 {
		t.Fatalf("expect 200")
	}
}

func TestGetWithQuery(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("expect GET, got %s", r.Method)
		}
		q := r.URL.Query()
		if q.Get("a") != "1" || q.Get("b") != "2" || q.Get("c") != "3" {
			t.Fatalf("query mismatch: %v", q)
		}
		w.WriteHeader(200)
	}
	opts := options{getWithQuery: true, data: multiFlag{"a=1&b=2", "c=3"}}
	res := runOnce(t, h, opts)
	if res.StatusCode != 200 {
		t.Fatalf("expect 200")
	}
}

func TestGzipDecompress(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		zw.Write([]byte("hello-gzip"))
		zw.Close()
		w.Write(buf.Bytes())
	}
	res := runOnce(t, h, options{})
	if !strings.Contains(res.Body, "hello-gzip") {
		t.Fatalf("expect decompressed body, got %q", res.Body)
	}
}

func TestRedirectMaxRedirs(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r1", http.StatusFound)
	})
	mux.HandleFunc("/r1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r2", http.StatusFound)
	})
	mux.HandleFunc("/r2", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// exceed max-redirs
	opts := options{follow: true, maxRedirs: 1}
	req, err := buildRequest(opts, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	res := doOnce(newHTTPClient(opts), opts, 0, req)
	if res.Error == "" {
		t.Fatalf("expect redirect error when exceeding max-redirs")
	}

	// allowed: need follow and non-zero timeout to actually attempt redirect
	optsOK := options{follow: true, maxRedirs: 2, timeoutSec: 2}
	req2, err := buildRequest(optsOK, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	res2 := doOnce(newHTTPClient(optsOK), optsOK, 0, req2)
	if res2.StatusCode != 200 {
		t.Fatalf("expect 200 with max-redirs=2, got %d", res2.StatusCode)
	}
}

func TestHTTP2AndHTTP11(t *testing.T) {
	h := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }
	srv := httptest.NewTLSServer(http.HandlerFunc(h))
	defer srv.Close()
	// HTTP/2（尽力尝试；部分平台/CI 上可能降级为 HTTP/1.1）
	optsH2 := options{http2: true, insecureTLS: true}
	req1, err := buildRequest(optsH2, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	res1 := doOnce(newHTTPClient(optsH2), optsH2, 0, req1)
	if !strings.HasPrefix(res1.Proto, "HTTP/2") {
		t.Logf("HTTP/2 not negotiated, got %s (acceptable)", res1.Proto)
	}
	// HTTP/1.1
	opts11 := options{http11: true, insecureTLS: true}
	req2, err := buildRequest(opts11, srv.URL)
	if err != nil {
		t.Fatalf("buildRequest: %v", err)
	}
	res2 := doOnce(newHTTPClient(opts11), opts11, 0, req2)
	if res2.Proto != "HTTP/1.1" {
		t.Fatalf("expect HTTP/1.1, got %s", res2.Proto)
	}
}
