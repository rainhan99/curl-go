package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptrace"
	"time"
)

type timings struct {
	DNSMs   int64 `json:"dns_ms"`
	TCPMs   int64 `json:"tcp_ms"`
	TLSMs   int64 `json:"tls_ms"`
	TTFBMs  int64 `json:"ttfb_ms"`
	TotalMs int64 `json:"total_ms"`
}

func attachTrace(req *http.Request) (*http.Request, *timings) {
	t := &timings{}
	var start, dnsStart, connStart, tlsStart time.Time
	start = time.Now()
	trace := &httptrace.ClientTrace{
		DNSStart: func(httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				t.DNSMs = time.Since(dnsStart).Milliseconds()
			}
		},
		ConnectStart: func(string, string) { connStart = time.Now() },
		ConnectDone: func(string, string, error) {
			if !connStart.IsZero() {
				t.TCPMs = time.Since(connStart).Milliseconds()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(tls.ConnectionState, error) {
			if !tlsStart.IsZero() {
				t.TLSMs = time.Since(tlsStart).Milliseconds()
			}
		},
		GotFirstResponseByte: func() { t.TTFBMs = time.Since(start).Milliseconds() },
	}
	ctx := httptrace.WithClientTrace(req.Context(), trace)
	req = req.WithContext(ctx)
	return req, t
}
