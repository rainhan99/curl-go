package main

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// copyAndMatch streams response body to writer and matches substring without extra peak memory
func copyAndMatch(dst io.Writer, src io.Reader, needle string) (matched bool, written int64, err error) {
	if needle == "" {
		n, err := io.Copy(dst, src)
		return false, n, err
	}
	buf := make([]byte, 32*1024)
	var tail []byte
	needleBytes := []byte(needle)
	maxTail := len(needleBytes) - 1
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			chunk := buf[:nr]
			if len(tail) > 0 {
				combined := append(tail, chunk...)
				if bytes.Contains(combined, needleBytes) {
					matched = true
				}
			} else if bytes.Contains(chunk, needleBytes) {
				matched = true
			}
			nw, ew := dst.Write(chunk)
			written += int64(nw)
			if ew != nil {
				return matched, written, ew
			}
			if nw != len(chunk) {
				return matched, written, io.ErrShortWrite
			}
			if maxTail > 0 {
				if len(chunk) >= maxTail {
					tail = append([]byte{}, chunk[len(chunk)-maxTail:]...)
				} else {
					need := maxTail
					if len(tail)+len(chunk) < need {
						need = len(tail) + len(chunk)
					}
					combined := append(tail, chunk...)
					tail = append([]byte{}, combined[len(combined)-need:]...)
				}
			}
		}
		if er != nil {
			if er == io.EOF {
				break
			}
			return matched, written, er
		}
	}
	return matched, written, nil
}

// streamOnce executes request and streams response to 'stream'. Used by -o/-O/-J or stdout streaming
func streamOnce(client *http.Client, opts options, index int, reqTemplate *http.Request, stream io.Writer, matchNeedle string) jsonResult {
	var req *http.Request
	if reqTemplate.GetBody != nil {
		bodyCopy, _ := reqTemplate.GetBody()
		req, _ = http.NewRequest(reqTemplate.Method, reqTemplate.URL.String(), bodyCopy)
	} else {
		var err error
		req, err = buildRequest(opts, reqTemplate.URL.String())
		if err != nil {
			return jsonResult{Index: index, URL: reqTemplate.URL.String(), Method: reqTemplate.Method, Error: err.Error()}
		}
	}
	for k, v := range reqTemplate.Header {
		for _, vv := range v {
			req.Header.Add(k, vv)
		}
	}

	req, t := attachTrace(req)
	start := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return jsonResult{Index: index, URL: req.URL.String(), Method: req.Method, Error: err.Error(), Timings: &timings{TotalMs: time.Since(start).Milliseconds()}}
	}
	defer resp.Body.Close()
	t.TotalMs = time.Since(start).Milliseconds()

	// -i 或 -I 都应打印响应头
	if opts.includeHdr || opts.headOnly {
		proto := resp.Proto
		if proto == "" {
			proto = "HTTP/1.1"
		}
		fmt.Fprintf(stream, "%s %s\n", proto, resp.Status)
		for k, vs := range resp.Header {
			for _, v := range vs {
				fmt.Fprintf(stream, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(stream)
	}

	var matched bool = true
	var written int64
	if !opts.headOnly && !opts.noBody {
		var dst io.Writer = stream
		if opts.failFast && resp.StatusCode >= 400 {
			dst = io.Discard
		}
		var reader io.Reader = resp.Body
		if !opts.rawBody && strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
			zr, zerr := gzip.NewReader(resp.Body)
			if zerr == nil {
				defer zr.Close()
				reader = zr
			}
		}
		var m bool
		m, written, err = copyAndMatch(dst, reader, matchNeedle)
		if err != nil {
			return jsonResult{Index: index, URL: req.URL.String(), Method: req.Method, Proto: resp.Proto, StatusCode: resp.StatusCode, Status: resp.Status, Headers: resp.Header, Error: err.Error(), Timings: t}
		}
		if matchNeedle != "" {
			matched = m
		}
	} else {
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<20)
	}

	jr := jsonResult{Index: index, URL: req.URL.String(), Method: req.Method, Proto: resp.Proto, StatusCode: resp.StatusCode, Status: resp.Status, Headers: resp.Header, BodySize: int(written), Timings: t, Matched: matched}
	return jr
}
