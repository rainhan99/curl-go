package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/textproto"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const version = "curl-go-v0.0.1"

var errHelp = errors.New("help")

// multiFlag moved to types.go

type options struct {
	method      string
	headers     multiFlag
	data        multiFlag
	jsonBody    string
	formFields  multiFlag
	includeHdr  bool
	headOnly    bool
	follow      bool
	insecureTLS bool
	timeoutSec  int
	outputFile  string
	basicAuth   string
	verbose     bool
	// removed: statusOnly (use --x-sc instead)
	proxyURL      string
	cookies       string
	rawBody       bool
	concurrency   int
	repeat        int
	expectString  string
	traceTimings  bool
	userAgent     string
	jsonOut       bool
	jsonBodyPlain bool
	// new flags (curl-compat)
	compressed       bool   // --compressed (hint header; Go auto handles)
	connectTimeout   int    // --connect-timeout seconds
	dumpHeaderFile   string // -D/--dump-header
	cookieJarFile    string // -c/--cookie-jar
	proxyAlias       string // -x/--proxy
	getWithQuery     bool   // -G
	urlQuery         string // --url-query
	rangeSpec        string // -r/--range
	failFast         bool   // -f/--fail
	retry            int    // --retry
	retryDelaySec    int    // --retry-delay
	retryMaxTimeSec  int    // --retry-max-time
	outputRemoteName bool   // -O
	remoteHeaderName bool   // -J
	outputDir        string // --output-dir
	createDirs       bool   // --create-dirs
	maxRedirs        int    // --max-redirs
	http10           bool   // --http1.0
	http11           bool   // --http1.1
	http2            bool   // --http2
	uploadFile       string // -T/--upload-file
	writeOut         string // -w/--write-out
	stderrFile       string // --stderr
	outputTemplate   string // --output-template 并发/多次时为每个请求生成独立文件
	// url encode additions
	urlEncData multiFlag // --data-urlencode 累加
	// load test
	durationSec  int    // --duration 秒
	ratePerSec   int    // --rate 每秒发送请求数（总速率）
	summaryOnly  bool   // --summary 仅汇总
	summaryJSON  bool   // --summary-json 输出汇总为 JSON
	noBody       bool   // --no-body 压测时不保留响应体（尽量丢弃）
	noJar        bool   // --no-jar 禁用 CookieJar
	maxBodyBytes int    // --max-body-bytes JSON 输出时保留的最大 body 字节数（0 不限）
	dataFile     string // --data-file 流式 application/x-www-form-urlencoded 请求体
	jsonFile     string // --json-file 流式 application/json 请求体
	helpLang     string // --help-lang zh|en
	pretty       bool   // --pretty human-readable summary
	noPretty     bool   // --no-pretty disable pretty summary
	// extract shortcuts
	xSC       bool      // --x-sc 输出状态码
	xServer   bool      // --x-server 输出Server响应头
	xCT       bool      // --x-ct 输出Content-Type
	xProto    bool      // --x-proto 输出协议
	xURL      bool      // --x-url 输出最终URL
	xLocation bool      // --x-loc 输出Location
	xHeaders  multiFlag // --x-header Name 可重复，输出指定响应头
	xSep      string    // --x-sep 分隔符，默认换行
}

// helpEN moved to help.go

func parseArgs(args []string) (opts options, targetURL string, err error) {
	fs := flag.NewFlagSet("curl-go", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var showHelp bool

	// help flags
	fs.BoolVar(&showHelp, "h", false, "显示帮助 / Show help")
	fs.BoolVar(&showHelp, "help", false, "显示帮助 / Show help")
	fs.StringVar(&opts.helpLang, "help-lang", "zh", "帮助语言: zh|en / Help language: zh|en")
	fs.StringVar(&opts.method, "X", "", "自定义 HTTP 方法")
	fs.Var(&opts.headers, "H", "添加请求头，可重复使用")
	fs.Var(&opts.data, "d", "请求体数据，可重复使用；支持 @file 或 @- 读取文件/标准输入")
	fs.Var(&opts.urlEncData, "data-urlencode", "URL 编码的数据 (name=value 或 @file)，可重复使用")
	fs.Var(&opts.formFields, "F", "multipart 表单字段，如 name=value 或 name=@file;type=...；可重复使用")
	fs.StringVar(&opts.jsonBody, "json", "", "以 JSON 方式发送数据，自动设置 Content-Type: application/json；支持 @file 或 @-")
	fs.BoolVar(&opts.includeHdr, "i", false, "输出时包含响应头")
	fs.BoolVar(&opts.headOnly, "I", false, "仅获取响应头 (HEAD)")
	fs.BoolVar(&opts.follow, "L", false, "跟随重定向")
	fs.BoolVar(&opts.insecureTLS, "k", false, "跳过 TLS 校验")
	fs.IntVar(&opts.timeoutSec, "m", 0, "超时(秒)，0 表示不设置")
	fs.StringVar(&opts.outputFile, "o", "", "将响应体写入文件")
	fs.StringVar(&opts.basicAuth, "u", "", "Basic 认证，格式 user:password")
	fs.BoolVar(&opts.verbose, "v", false, "输出详细调试信息")
	// 已移除 --status-only（请使用 --x-sc）
	fs.StringVar(&opts.proxyURL, "proxy", "", "HTTP 代理，如 http://127.0.0.1:8080")
	fs.StringVar(&opts.proxyURL, "x", "", "代理 (-x) 与 --proxy 等价")
	fs.StringVar(&opts.cookies, "b", "", "设置 Cookie，如 'a=1; b=2' 或 @file")
	fs.BoolVar(&opts.rawBody, "raw", false, "获取原始压缩响应体（禁用自动解压）")
	fs.IntVar(&opts.concurrency, "concurrency", 1, "并发数")
	fs.IntVar(&opts.repeat, "repeat", 1, "重复请求次数（总计次数=repeat）")
	fs.StringVar(&opts.expectString, "expect-string", "", "检测响应体中是否包含该固定字符串，不包含则退出码为 22")
	fs.BoolVar(&opts.traceTimings, "trace", false, "输出耗时分析（DNS/TCP/TLS/TTFB/Total）")
	fs.StringVar(&opts.userAgent, "A", version, "User-Agent 值")
	fs.BoolVar(&opts.jsonOut, "json-out", false, "以 JSON 输出结果")
	fs.BoolVar(&opts.jsonBodyPlain, "json-body-plain", false, "JSON 输出时，body 以明文字符串而非 base64（可能出现编码问题）")
	fs.BoolVar(&opts.compressed, "compressed", false, "请求压缩响应 (自动添加 Accept-Encoding:gzip)")
	fs.IntVar(&opts.connectTimeout, "connect-timeout", 0, "连接超时(秒)")
	fs.StringVar(&opts.dumpHeaderFile, "D", "", "将响应头写入文件 (-D)")
	fs.StringVar(&opts.dumpHeaderFile, "dump-header", "", "将响应头写入文件")
	fs.StringVar(&opts.cookieJarFile, "c", "", "操作结束后将 Cookie 写入文件 (-c)")
	fs.StringVar(&opts.cookieJarFile, "cookie-jar", "", "操作结束后将 Cookie 写入文件")
	// 移除重复绑定，统一使用 opts.proxyURL
	fs.BoolVar(&opts.getWithQuery, "G", false, "将 -d 拼接到 URL 上并使用 GET")
	fs.StringVar(&opts.urlQuery, "url-query", "", "附加 URL 查询串 name=value&k=v")
	fs.StringVar(&opts.rangeSpec, "r", "", "范围请求 (-r)")
	fs.StringVar(&opts.rangeSpec, "range", "", "范围请求")
	fs.BoolVar(&opts.failFast, "f", false, "HTTP 错误码时不输出正文 (-f)")
	fs.BoolVar(&opts.failFast, "fail", false, "HTTP 错误码时不输出正文")
	fs.IntVar(&opts.retry, "retry", 0, "重试次数")
	fs.IntVar(&opts.retryDelaySec, "retry-delay", 0, "重试间隔秒")
	fs.IntVar(&opts.retryMaxTimeSec, "retry-max-time", 0, "重试的最长总时长（秒）")
	fs.BoolVar(&opts.outputRemoteName, "O", false, "使用远端文件名保存 (-O)")
	fs.BoolVar(&opts.remoteHeaderName, "J", false, "使用响应头中的文件名 (-J)")
	fs.StringVar(&opts.outputDir, "output-dir", "", "输出目录")
	fs.BoolVar(&opts.createDirs, "create-dirs", false, "创建必要的本地目录")
	fs.IntVar(&opts.maxRedirs, "max-redirs", 0, "最大重定向次数")
	fs.BoolVar(&opts.http10, "http1.0", false, "使用 HTTP/1.0")
	fs.BoolVar(&opts.http11, "http1.1", false, "使用 HTTP/1.1")
	fs.BoolVar(&opts.http2, "http2", false, "使用 HTTP/2")
	fs.StringVar(&opts.uploadFile, "T", "", "上传文件 (-T)")
	fs.StringVar(&opts.uploadFile, "upload-file", "", "上传文件")
	fs.StringVar(&opts.writeOut, "w", "", "完成后输出格式 (-w)")
	fs.StringVar(&opts.writeOut, "write-out", "", "完成后输出格式")
	fs.StringVar(&opts.stderrFile, "stderr", "", "将 stderr 重定向到文件")
	// extract 快捷输出
	fs.BoolVar(&opts.xSC, "x-sc", false, "仅输出状态码")
	fs.BoolVar(&opts.xServer, "x-server", false, "仅输出响应头 Server")
	fs.BoolVar(&opts.xCT, "x-ct", false, "仅输出响应头 Content-Type")
	fs.BoolVar(&opts.xProto, "x-proto", false, "仅输出协议版本")
	fs.BoolVar(&opts.xURL, "x-url", false, "仅输出最终URL")
	fs.BoolVar(&opts.xLocation, "x-loc", false, "仅输出响应头 Location")
	fs.Var(&opts.xHeaders, "x-header", "输出指定响应头，可重复使用，如 --x-header Server")
	fs.StringVar(&opts.xSep, "x-sep", "\n", "多个提取项的分隔符，默认换行")
	fs.StringVar(&opts.outputTemplate, "output-template", "", "并发/多次模式的输出文件模板，如 out-{index}.bin 或 logs/{index}.txt")
	// load test flags
	fs.IntVar(&opts.durationSec, "duration", 0, "压测持续时间（秒），>0 时与 --rate 配合进行限流压测")
	fs.IntVar(&opts.ratePerSec, "rate", 0, "每秒请求数上限（RPS）")
	fs.BoolVar(&opts.summaryOnly, "summary", false, "仅输出汇总统计")
	fs.BoolVar(&opts.summaryJSON, "summary-json", false, "输出压测汇总为 JSON")
	fs.BoolVar(&opts.noBody, "no-body", false, "压测时不保留响应体以减少内存占用")
	fs.BoolVar(&opts.noJar, "no-jar", false, "禁用 CookieJar（压测建议开启）")
	fs.IntVar(&opts.maxBodyBytes, "max-body-bytes", 0, "JSON 输出时最多保留的 body 大小（字节，0 表示不限）")
	// 流式请求体文件
	fs.StringVar(&opts.dataFile, "data-file", "", "以文件作为 x-www-form-urlencoded 请求体（流式）")
	fs.StringVar(&opts.jsonFile, "json-file", "", "以文件作为 application/json 请求体（流式）")
	// pretty summary toggle
	fs.BoolVar(&opts.pretty, "pretty", true, "Pretty summary output")
	fs.BoolVar(&opts.noPretty, "no-pretty", false, "Disable pretty summary output")

	if err = fs.Parse(args); err != nil {
		return opts, "", err
	}

	remaining := fs.Args()
	if showHelp || len(remaining) == 0 {
		// Print bilingual or selected language help with a short readable header
		fs.SetOutput(os.Stdout)
		if opts.helpLang == "en" {
			fmt.Fprintf(os.Stdout, "Usage: curl-go [options...] <url>\n")
			fmt.Fprintf(os.Stdout, "Tip: use --json, -F, -d, --data-urlencode, -o/-O/-J, -L, --trace, --summary.\n\n")
			// Custom English help using mapping
			fs.VisitAll(func(f *flag.Flag) {
				desc := f.Usage
				if v, ok := helpEN[f.Name]; ok {
					desc = v
				}
				def := strings.TrimSpace(f.DefValue)
				if def != "" && def != "false" && def != "0" {
					fmt.Fprintf(os.Stdout, "  -%s\n      %s (default %s)\n", f.Name, desc, def)
					return
				}
				fmt.Fprintf(os.Stdout, "  -%s\n      %s\n", f.Name, desc)
			})
			return opts, "", errHelp
		} else {
			fmt.Fprintf(os.Stdout, "用法: curl-go [参数...] <url>\n")
			fmt.Fprintf(os.Stdout, "提示: 常用 --json、-F、-d、--data-urlencode、-o/-O/-J、-L、--trace、--summary。\n\n")
			fs.VisitAll(func(f *flag.Flag) {
				// --status-only 已移除，无需展示
				if f.Name == "status-only" {
					return
				}
				desc := f.Usage
				def := strings.TrimSpace(f.DefValue)
				if def != "" && def != "false" && def != "0" {
					fmt.Fprintf(os.Stdout, "  -%s\n      %s (默认 %s)\n", f.Name, desc, def)
					return
				}
				fmt.Fprintf(os.Stdout, "  -%s\n      %s\n", f.Name, desc)
			})
			return opts, "", errHelp
		}
		// 英文路径已在上面 return，此处无需再打印
		return opts, "", errHelp
	}
	targetURL = remaining[0]

	// 参数互斥与优先级
	if opts.rawBody && opts.compressed {
		return opts, "", errors.New("--raw 与 --compressed 互斥")
	}
	if opts.headOnly && opts.noBody {
		// -I 语义更强：仅头
		opts.noBody = false
	}
	if opts.outputFile != "" && (opts.outputRemoteName || opts.remoteHeaderName) {
		// 明确 -o 优先
		opts.outputRemoteName = false
		opts.remoteHeaderName = false
	}
	if opts.durationSec > 0 && opts.ratePerSec > 0 && opts.repeat > 1 {
		// 优先 duration/rate 模式
		opts.repeat = 0
	}

	return opts, targetURL, nil
}

func buildRequest(opts options, targetURL string) (*http.Request, error) {
	// Parse URL and auto-prepend scheme if missing
	if !strings.Contains(targetURL, "://") {
		targetURL = "http://" + targetURL
	}
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("无效的 URL: %w", err)
	}

	// Infer HTTP method
	method := strings.ToUpper(strings.TrimSpace(opts.method))
	if opts.headOnly {
		method = "HEAD"
	}
	if method == "" {
		if len(opts.formFields) > 0 || len(opts.data) > 0 || len(opts.urlEncData) > 0 || strings.TrimSpace(opts.jsonBody) != "" {
			method = "POST"
		} else {
			method = "GET"
		}
	}

	// -G: append -d data to query string
	if opts.getWithQuery && len(opts.data) > 0 {
		q := parsed.Query()
		for _, item := range opts.data {
			payload, err := readPayload(item)
			if err != nil {
				return nil, err
			}
			// 支持 a=b&c=d 拼接
			for _, kv := range strings.Split(payload, "&") {
				if kv == "" {
					continue
				}
				k, v, ok := strings.Cut(kv, "=")
				if !ok {
					q.Add(kv, "")
					continue
				}
				q.Add(k, v)
			}
		}
		parsed.RawQuery = q.Encode()
		// 置空 data 以避免 body 再次使用，并强制 GET 方法
		opts.data = nil
		method = "GET"
	}

	// Append --url-query parameters
	if strings.TrimSpace(opts.urlQuery) != "" {
		q := parsed.Query()
		for _, kv := range strings.Split(opts.urlQuery, "&") {
			if kv == "" {
				continue
			}
			k, v, ok := strings.Cut(kv, "=")
			if !ok {
				q.Add(kv, "")
				continue
			}
			q.Add(k, v)
		}
		parsed.RawQuery = q.Encode()
	}

	// Build request body
	var bodyReader io.Reader
	var bodyBytes []byte

	// Validate mutual exclusivity among -F/-d/--json/--data-file/--json-file
	usedBodyKinds := 0
	if len(opts.formFields) > 0 {
		usedBodyKinds++
	}
	if len(opts.data) > 0 {
		usedBodyKinds++
	}
	if strings.TrimSpace(opts.jsonBody) != "" {
		usedBodyKinds++
	}
	if len(opts.urlEncData) > 0 {
		usedBodyKinds++
	}
	if strings.TrimSpace(opts.dataFile) != "" {
		usedBodyKinds++
	}
	if strings.TrimSpace(opts.jsonFile) != "" {
		usedBodyKinds++
	}
	if usedBodyKinds > 1 {
		return nil, errors.New("-F/-d/--json/--data-file/--json-file 只能选择一种")
	}

	// -T/--upload-file is mutually exclusive with -F/-d/--json/--data-file/--json-file
	if strings.TrimSpace(opts.uploadFile) != "" {
		if len(opts.formFields) > 0 || len(opts.data) > 0 || strings.TrimSpace(opts.jsonBody) != "" || strings.TrimSpace(opts.dataFile) != "" || strings.TrimSpace(opts.jsonFile) != "" {
			return nil, errors.New("-T 与 -F/-d/--json/--data-file/--json-file 互斥")
		}
		if method == "GET" || method == "" {
			method = "PUT"
		}
		fp := filepath.Clean(opts.uploadFile)
		f, err := os.Open(fp)
		if err != nil {
			return nil, err
		}
		bodyReader = f
	}

	// Streaming non-multipart request body
	if strings.TrimSpace(opts.dataFile) != "" || strings.TrimSpace(opts.jsonFile) != "" {
		var fp string
		var ctype string
		if strings.TrimSpace(opts.jsonFile) != "" {
			fp = strings.TrimSpace(opts.jsonFile)
			ctype = "application/json"
		} else {
			fp = strings.TrimSpace(opts.dataFile)
			ctype = "application/x-www-form-urlencoded"
		}
		var bodyRC io.ReadCloser
		var isStdin bool
		var filePath string
		if fp == "-" {
			bodyRC = io.NopCloser(os.Stdin)
			isStdin = true
		} else {
			filePath = filepath.Clean(fp)
			f, err := os.Open(filePath)
			if err != nil {
				return nil, err
			}
			bodyRC = f
		}
		if method == "GET" || method == "" {
			method = "POST"
		}
		req, err := http.NewRequest(method, parsed.String(), bodyRC)
		if err != nil {
			if !isStdin {
				bodyRC.Close()
			}
			return nil, err
		}
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", ctype)
		}
		if !isStdin && filePath != "" {
			if fi, err := os.Stat(filePath); err == nil {
				req.ContentLength = fi.Size()
			}
			req.GetBody = func() (io.ReadCloser, error) { return os.Open(filePath) }
		}
		// 默认 UA 与头/认证/Cookie 与普通路径一致
		if opts.userAgent != "" {
			req.Header.Set("User-Agent", opts.userAgent)
		} else {
			req.Header.Set("User-Agent", version)
		}
		for _, h := range opts.headers {
			name, value, ok := strings.Cut(h, ":")
			if !ok {
				if !isStdin {
					bodyRC.Close()
				}
				return nil, fmt.Errorf("无效头部: %s，应为 'Name: value'", h)
			}
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name == "" {
				if !isStdin {
					bodyRC.Close()
				}
				return nil, fmt.Errorf("无效头部: %s", h)
			}
			req.Header.Add(name, value)
		}
		if strings.TrimSpace(opts.basicAuth) != "" {
			user, pass, ok := strings.Cut(opts.basicAuth, ":")
			if !ok {
				user = opts.basicAuth
				pass = ""
			}
			token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			req.Header.Set("Authorization", "Basic "+token)
		}
		if strings.TrimSpace(opts.cookies) != "" {
			pairs := strings.Split(opts.cookies, ";")
			for _, p := range pairs {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				name, val, ok := strings.Cut(p, "=")
				if !ok {
					continue
				}
				req.AddCookie(&http.Cookie{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)})
			}
		}
		return req, nil
	}

	// multipart 表单
	if len(opts.formFields) > 0 {
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		for _, f := range opts.formFields {
			name, val, ok := strings.Cut(f, "=")
			if !ok {
				return nil, fmt.Errorf("无效 -F 字段: %s，应为 name=value 或 name=@file", f)
			}
			name = strings.TrimSpace(name)
			val = strings.TrimSpace(val)
			if strings.HasPrefix(val, "@") {
				// Parse optional type hint: name=@file;type=...
				fileSpec := strings.TrimPrefix(val, "@")
				filePath := fileSpec
				contentType := ""
				if semi := strings.Index(fileSpec, ";"); semi != -1 {
					filePath = fileSpec[:semi]
					params := fileSpec[semi+1:]
					for _, p := range strings.Split(params, ";") {
						p = strings.TrimSpace(p)
						if strings.HasPrefix(strings.ToLower(p), "type=") {
							contentType = strings.TrimSpace(strings.TrimPrefix(p, "type="))
						}
					}
				}
				filePath = filepath.Clean(filePath)
				file, err := os.Open(filePath)
				if err != nil {
					return nil, err
				}
				if contentType != "" {
					h := make(textproto.MIMEHeader)
					h.Set("Content-Disposition", fmt.Sprintf("form-data; name=\"%s\"; filename=\"%s\"", name, filepath.Base(filePath)))
					h.Set("Content-Type", contentType)
					part, err := mw.CreatePart(h)
					if err != nil {
						file.Close()
						return nil, err
					}
					if _, err := io.Copy(part, file); err != nil {
						file.Close()
						return nil, err
					}
				} else {
					part, err := mw.CreateFormFile(name, filepath.Base(filePath))
					if err != nil {
						file.Close()
						return nil, err
					}
					if _, err := io.Copy(part, file); err != nil {
						file.Close()
						return nil, err
					}
				}
				file.Close()
			} else {
				if err := mw.WriteField(name, val); err != nil {
					return nil, err
				}
			}
		}
		if err := mw.Close(); err != nil {
			return nil, err
		}
		bodyBytes = buf.Bytes()
		bodyReader = bytes.NewReader(bodyBytes)
		req, err := http.NewRequest(method, parsed.String(), bodyReader)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(bodyBytes)), nil }
		// Default User-Agent
		if opts.userAgent != "" {
			req.Header.Set("User-Agent", opts.userAgent)
		} else {
			req.Header.Set("User-Agent", version)
		}
		// Headers
		for _, h := range opts.headers {
			name, value, ok := strings.Cut(h, ":")
			if !ok {
				return nil, fmt.Errorf("无效头部: %s，应为 'Name: value'", h)
			}
			name = strings.TrimSpace(name)
			value = strings.TrimSpace(value)
			if name == "" {
				return nil, fmt.Errorf("无效头部: %s", h)
			}
			req.Header.Add(name, value)
		}
		// Basic/Cookie are set below
		// Set content length according to body
		req.ContentLength = int64(len(bodyBytes))
		// Basic Auth
		if strings.TrimSpace(opts.basicAuth) != "" {
			user, pass, ok := strings.Cut(opts.basicAuth, ":")
			if !ok {
				user = opts.basicAuth
				pass = ""
			}
			token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
			req.Header.Set("Authorization", "Basic "+token)
		}
		// Cookies
		if strings.TrimSpace(opts.cookies) != "" {
			pairs := strings.Split(opts.cookies, ";")
			for _, p := range pairs {
				p = strings.TrimSpace(p)
				if p == "" {
					continue
				}
				name, val, ok := strings.Cut(p, "=")
				if !ok {
					continue
				}
				c := &http.Cookie{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)}
				req.AddCookie(c)
			}
		}
		return req, nil
	}

	// 处理 --json 优先
	if strings.TrimSpace(opts.jsonBody) != "" {
		jsonPayload, err := readPayload(opts.jsonBody)
		if err != nil {
			return nil, err
		}
		bodyBytes = []byte(jsonPayload)
		bodyReader = bytes.NewReader(bodyBytes)
	} else if len(opts.data) > 0 {
		// curl 语义：多个 -d 默认以 & 连接
		var parts []string
		for _, item := range opts.data {
			payload, err := readPayload(item)
			if err != nil {
				return nil, err
			}
			parts = append(parts, payload)
		}
		bodyBytes = []byte(strings.Join(parts, "&"))
		bodyReader = bytes.NewReader(bodyBytes)
	} else if len(opts.urlEncData) > 0 {
		var dataParts []string
		for _, arg := range opts.urlEncData {
			if strings.HasPrefix(arg, "@") {
				txt, err := readPayload(arg)
				if err != nil {
					return nil, err
				}
				dataParts = append(dataParts, url.QueryEscape(txt))
				continue
			}
			if i := strings.IndexByte(arg, '='); i >= 0 {
				name := arg[:i]
				value := arg[i+1:]
				if strings.HasPrefix(value, "@") {
					txt, err := readPayload(value)
					if err != nil {
						return nil, err
					}
					dataParts = append(dataParts, url.QueryEscape(name)+"="+url.QueryEscape(txt))
				} else {
					dataParts = append(dataParts, url.QueryEscape(name)+"="+url.QueryEscape(value))
				}
				continue
			}
			dataParts = append(dataParts, url.QueryEscape(arg))
		}
		bodyBytes = []byte(strings.Join(dataParts, "&"))
		bodyReader = bytes.NewReader(bodyBytes)
	}

	req, err := http.NewRequest(method, parsed.String(), bodyReader)
	if err != nil {
		return nil, err
	}

	// 默认 UA
	if opts.userAgent != "" {
		req.Header.Set("User-Agent", opts.userAgent)
	} else {
		req.Header.Set("User-Agent", version)
	}

	// 头
	for _, h := range opts.headers {
		name, value, ok := strings.Cut(h, ":")
		if !ok {
			return nil, fmt.Errorf("无效头部: %s，应为 'Name: value'", h)
		}
		name = strings.TrimSpace(name)
		value = strings.TrimSpace(value)
		if name == "" {
			return nil, fmt.Errorf("无效头部: %s", h)
		}
		req.Header.Add(name, value)
	}

	// Auto set Content-Type based on body
	if bodyReader != nil {
		if strings.TrimSpace(opts.jsonBody) != "" {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/json")
			}
		} else if strings.TrimSpace(opts.uploadFile) != "" {
			if req.Header.Get("Content-Type") == "" {
				req.Header.Set("Content-Type", "application/octet-stream")
			}
		} else if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if len(bodyBytes) > 0 {
			req.ContentLength = int64(len(bodyBytes))
			req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(bodyBytes)), nil }
		}
	}

	// Range request header
	if strings.TrimSpace(opts.rangeSpec) != "" {
		req.Header.Set("Range", "bytes="+strings.TrimSpace(opts.rangeSpec))
	}

	// --compressed hint: explicitly send Accept-Encoding: gzip
	if opts.compressed {
		if req.Header.Get("Accept-Encoding") == "" {
			req.Header.Set("Accept-Encoding", "gzip")
		}
	}

	// Basic Auth
	if strings.TrimSpace(opts.basicAuth) != "" {
		user, pass, ok := strings.Cut(opts.basicAuth, ":")
		if !ok {
			user = opts.basicAuth
			pass = ""
		}
		token := base64.StdEncoding.EncodeToString([]byte(user + ":" + pass))
		req.Header.Set("Authorization", "Basic "+token)
	}

	// Cookies (-b): support loading from file (as @filename or plain filename)
	if strings.TrimSpace(opts.cookies) != "" {
		spec := strings.TrimSpace(opts.cookies)
		content := spec
		if strings.HasPrefix(spec, "@") || fileExists(spec) {
			p := strings.TrimPrefix(spec, "@")
			if data, err := os.ReadFile(filepath.Clean(p)); err == nil {
				content = string(data)
			}
		}
		// Parse name=value; name2=value2 or one per line
		for _, seg := range strings.FieldsFunc(content, func(r rune) bool { return r == ';' || r == '\n' || r == '\r' }) {
			s := strings.TrimSpace(seg)
			if s == "" || strings.HasPrefix(s, "#") {
				continue
			}
			name, val, ok := strings.Cut(s, "=")
			if !ok {
				continue
			}
			c := &http.Cookie{Name: strings.TrimSpace(name), Value: strings.TrimSpace(val)}
			req.AddCookie(c)
		}
	}

	// Explicit HTTP/1.0
	if opts.http10 {
		req.Proto = "HTTP/1.0"
		req.ProtoMajor, req.ProtoMinor = 1, 0
		req.Close = true
	}

	return req, nil
}

func newHTTPClient(opts options) *http.Client {
	transport := &http.Transport{
		MaxIdleConns:        1024,
		MaxIdleConnsPerHost: 256,
		IdleConnTimeout:     90 * time.Second,
	}
	if opts.insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}
	// HTTP version control
	if opts.http11 {
		// 禁用 HTTP/2
		transport.ForceAttemptHTTP2 = false
		transport.TLSNextProto = map[string]func(authority string, c *tls.Conn) http.RoundTripper{}
	} else if opts.http2 {
		transport.ForceAttemptHTTP2 = true
		// 其余保持默认启用 ALPN
	}
	if opts.proxyURL != "" {
		if purl, err := url.Parse(opts.proxyURL); err == nil {
			transport.Proxy = http.ProxyURL(purl)
		}
	}
	// Disable automatic decompression when rawBody=true
	transport.DisableCompression = opts.rawBody

	var jar http.CookieJar
	if !opts.noJar {
		jar, _ = cookiejar.New(nil)
	}
	client := &http.Client{Transport: transport, Jar: jar}
	// Do not follow redirects unless -L is set
	if !opts.follow {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 阻止自动跟随，但返回上一响应给调用方
			return http.ErrUseLastResponse
		}
	}
	// Set connect and overall timeouts
	if opts.timeoutSec > 0 {
		client.Timeout = time.Duration(opts.timeoutSec) * time.Second
	}
	if opts.connectTimeout > 0 {
		// 通过 Dialer 控制连接阶段超时
		d := &net.Dialer{Timeout: time.Duration(opts.connectTimeout) * time.Second}
		if transport.DialContext != nil {
			// 覆盖
		}
		transport.DialContext = d.DialContext
	}
	// Max redirects guard
	if opts.maxRedirs > 0 && opts.follow {
		max := opts.maxRedirs
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			// 允许最多 max 次重定向：当历史重定向次数严格大于 max 时才报错
			if len(via) > max {
				return errors.New("stopped after max-redirs")
			}
			return nil
		}
	}
	return client
}

func readAll(r io.Reader) ([]byte, error) {
	buf := bufio.NewReader(r)
	var out bytes.Buffer
	if _, err := out.ReadFrom(buf); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func readPayload(spec string) (string, error) {
	spec = strings.TrimSpace(spec)
	if spec == "" {
		return "", nil
	}
	if strings.HasPrefix(spec, "@") {
		path := strings.TrimPrefix(spec, "@")
		if path == "-" { // 从 stdin 读取
			data, err := readAll(os.Stdin)
			if err != nil {
				return "", err
			}
			return string(data), nil
		}
		data, err := os.ReadFile(filepath.Clean(path))
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	return spec, nil
}

func fileExists(p string) bool {
	if strings.TrimSpace(p) == "" {
		return false
	}
	// linter: unconditional TrimPrefix is equivalent and simpler
	p = strings.TrimPrefix(p, "@")
	if fi, err := os.Stat(filepath.Clean(p)); err == nil && !fi.IsDir() {
		return true
	}
	return false
}

// printResponseHeaders kept for reference and used in stream path
func printResponseHeaders(w io.Writer, resp *http.Response) {
	proto := resp.Proto
	status := resp.Status
	fmt.Fprintf(w, "%s %s\n", proto, status)
	for k, vals := range resp.Header {
		for _, v := range vals {
			fmt.Fprintf(w, "%s: %s\n", k, v)
		}
	}
	fmt.Fprintln(w)
}

// timings and attachTrace moved to trace.go

type jsonResult struct {
	Index      int                 `json:"index"`
	URL        string              `json:"url"`
	Method     string              `json:"method"`
	Proto      string              `json:"proto"`
	StatusCode int                 `json:"status_code"`
	Status     string              `json:"status"`
	Headers    map[string][]string `json:"headers"`
	BodyBase64 string              `json:"body_base64,omitempty"`
	Body       string              `json:"body,omitempty"`
	BodySize   int                 `json:"body_size"`
	Timings    *timings            `json:"timings,omitempty"`
	Matched    bool                `json:"matched"`
	Error      string              `json:"error,omitempty"`
}

// copyAndMatch moved to stream.go

// summary types and histogram moved to types.go

func readResponseBody(resp *http.Response, raw bool) ([]byte, error) {
	if raw {
		return io.ReadAll(resp.Body)
	}
	if strings.EqualFold(resp.Header.Get("Content-Encoding"), "gzip") {
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return io.ReadAll(resp.Body)
		}
		defer zr.Close()
		return io.ReadAll(zr)
	}
	return io.ReadAll(resp.Body)
}

// streamOnce moved to stream.go

func doOnce(client *http.Client, opts options, index int, reqTemplate *http.Request) jsonResult {
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
	// 重试逻辑（简单版本）
	var resp *http.Response
	var err error
	startRetryWindow := time.Now()
	for attempt := 0; ; attempt++ {
		resp, err = client.Do(req)
		transient := err != nil
		if !transient && opts.failFast && resp.StatusCode >= 400 {
			// 视为失败且不输出正文
			transient = false
		}
		if !transient {
			break
		}
		if attempt >= opts.retry {
			break
		}
		if opts.retryMaxTimeSec > 0 && time.Since(startRetryWindow) > time.Duration(opts.retryMaxTimeSec)*time.Second {
			break
		}
		delay := time.Duration(opts.retryDelaySec) * time.Second
		if delay <= 0 {
			delay = 1 * time.Second
		}
		time.Sleep(delay)
	}
	if err != nil {
		return jsonResult{Index: index, URL: req.URL.String(), Method: req.Method, Error: err.Error(), Timings: &timings{TotalMs: time.Since(start).Milliseconds()}}
	}
	defer resp.Body.Close()
	t.TotalMs = time.Since(start).Milliseconds()

	var bodyBytes []byte
	if !opts.headOnly && !opts.noBody {
		bb, err := readResponseBody(resp, opts.rawBody)
		if err != nil {
			return jsonResult{Index: index, URL: req.URL.String(), Method: req.Method, StatusCode: resp.StatusCode, Status: resp.Status, Headers: resp.Header, Error: err.Error(), Timings: t}
		}
		if opts.maxBodyBytes > 0 && len(bb) > opts.maxBodyBytes {
			bodyBytes = bb[:opts.maxBodyBytes]
		} else {
			bodyBytes = bb
		}
	} else {
		_, _ = io.CopyN(io.Discard, resp.Body, 1<<20)
	}

	matched := true
	if opts.expectString != "" {
		matched = bytes.Contains(bodyBytes, []byte(opts.expectString))
	}

	// 在 failFast 下，抑制正文在所有输出模式中的暴露（包括 JSON 输出）
	if opts.failFast && resp.StatusCode >= 400 {
		bodyBytes = nil
	}

	jr := jsonResult{
		Index:      index,
		URL:        req.URL.String(),
		Method:     req.Method,
		Proto:      resp.Proto,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Headers:    resp.Header,
		BodySize:   len(bodyBytes),
		Timings:    t,
		Matched:    matched,
	}
	if !opts.headOnly {
		if opts.jsonOut && !opts.jsonBodyPlain {
			jr.BodyBase64 = base64.StdEncoding.EncodeToString(bodyBytes)
		} else {
			jr.Body = string(bodyBytes)
		}
	}
	jr.Matched = matched
	return jr
}

func main() {
	opts, targetURL, err := parseArgs(os.Args[1:])
	if err != nil {
		if errors.Is(err, errHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}

	// --stderr: 重定向标准错误到文件
	if strings.TrimSpace(opts.stderrFile) != "" {
		f, ferr := os.Create(opts.stderrFile)
		if ferr != nil {
			fmt.Fprintln(os.Stderr, "无法打开 --stderr 文件:", ferr)
			os.Exit(2)
		}
		// 不在此处关闭，进程退出时由系统回收；确保整个运行期间 stderr 都重定向
		os.Stderr = f
	}

	// 提取模式：若用户未显式指定方法或请求体，优先用 HEAD 提高响应速度，并避免读取正文
	isExtract := opts.xSC || opts.xServer || opts.xCT || opts.xProto || opts.xURL || opts.xLocation || len(opts.xHeaders) > 0
	if isExtract {
		// 未指定方法且无请求体相关参数时，切换为 HEAD
		noBodyInput := len(opts.formFields) == 0 && len(opts.data) == 0 && len(opts.urlEncData) == 0 && strings.TrimSpace(opts.jsonBody) == "" && strings.TrimSpace(opts.uploadFile) == "" && strings.TrimSpace(opts.dataFile) == "" && strings.TrimSpace(opts.jsonFile) == ""
		if strings.TrimSpace(opts.method) == "" && noBodyInput {
			opts.headOnly = true
		}
		// 不读取正文以减少延迟
		opts.noBody = true
	}

	req, err := buildRequest(opts, targetURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "构建请求失败:", err)
		os.Exit(2)
	}

	if opts.verbose {
		fmt.Fprintf(os.Stderr, "> %s %s\n", req.Method, req.URL)
		for k, vals := range req.Header {
			for _, v := range vals {
				fmt.Fprintf(os.Stderr, "> %s: %s\n", k, v)
			}
		}
		if req.ContentLength > 0 {
			fmt.Fprintf(os.Stderr, "> Content-Length: %d\n", req.ContentLength)
		}
	}

	client := newHTTPClient(opts)

	multi := opts.concurrency > 1 || opts.repeat > 1 || opts.jsonOut || (opts.durationSec > 0 && opts.ratePerSec > 0)
	if multi && opts.outputFile != "" {
		fmt.Fprintln(os.Stderr, "并发/多次模式下暂不支持 -o 输出到同一文件，请移除 -o 或仅单次请求")
		os.Exit(2)
	}

	if multi {
		type item struct{ idx int }
		var results []jsonResult
		var wg sync.WaitGroup
		workers := opts.concurrency
		if workers < 1 {
			workers = 1
		}
		if opts.durationSec > 0 && opts.ratePerSec > 0 {
			// 压测模式默认禁用 Jar 和 body（可被用户覆盖），并设置保守超时防止阻塞
			recreate := false
			if !opts.noJar {
				opts.noJar = true
				recreate = true
			}
			if !opts.noBody {
				opts.noBody = true
			}
			// 若用户未显式设置整体超时与连接超时，设置合理默认值，避免卡死
			if opts.timeoutSec == 0 {
				opts.timeoutSec = 5
				recreate = true
			}
			if opts.connectTimeout == 0 {
				opts.connectTimeout = 3
				recreate = true
			}
			if recreate {
				client = newHTTPClient(opts)
			}
			total := opts.durationSec * opts.ratePerSec
			if total < 1 {
				total = 1
			}
			// 使用带缓冲通道，缓冲至少为 rate 或 64，避免高 RPS 时生产阻塞
			bufSize := opts.ratePerSec
			if bufSize < 64 {
				bufSize = 64
			}
			jobs := make(chan item, bufSize)
			ticker := time.NewTicker(time.Second / time.Duration(opts.ratePerSec))
			defer ticker.Stop()
			// summary 模式：边执行边聚合，避免分配大切片
			if opts.summaryOnly || opts.summaryJSON {
				stats := summaryStats{Concurrency: workers, DurationSec: opts.durationSec, RatePerSec: opts.ratePerSec, StatusCodes: map[int]int{}}
				hist := newLatencyHist(5, 2000)
				var mu sync.Mutex
				// 进度输出：每秒打印一次当前统计，避免用户误判无输出
				progressDone := make(chan struct{})
				go func(total int) {
					tk := time.NewTicker(1 * time.Second)
					defer tk.Stop()
					if !opts.noPretty {
						fmt.Fprintf(os.Stderr, "[progress] start total=%d concurrency=%d rate=%drps\n", total, workers, opts.ratePerSec)
					}
					for {
						select {
						case <-progressDone:
							return
						case <-tk.C:
							if opts.noPretty {
								continue
							}
							mu.Lock()
							curTotal := stats.TotalRequests + stats.ErrorCount
							succ := stats.SuccessCount
							err := stats.ErrorCount
							mu.Unlock()
							fmt.Fprintf(os.Stderr, "[progress] done=%d/%d success=%d errors=%d\n", curTotal, total, succ, err)
						}
					}
				}(total)
				// 先启动 worker，再开始投递任务
				for w := 0; w < workers; w++ {
					wg.Add(1)
					go func() {
						defer wg.Done()
						for range jobs {
							r := doOnce(client, opts, 0, req)
							mu.Lock()
							if r.Error != "" {
								stats.ErrorCount++
								mu.Unlock()
								continue
							}
							stats.TotalRequests++
							stats.StatusCodes[r.StatusCode]++
							if r.StatusCode >= 200 && r.StatusCode < 400 {
								stats.SuccessCount++
							} else {
								stats.ErrorCount++
							}
							stats.BytesTotal += int64(r.BodySize)
							if r.Timings != nil {
								hist.add(r.Timings.TotalMs)
							}
							mu.Unlock()
						}
					}()
				}
				go func() {
					for i := 0; i < total; i++ {
						<-ticker.C
						jobs <- item{idx: i}
					}
					close(jobs)
				}()
				wg.Wait()
				close(progressDone)
				stats.LatencyMsP50 = hist.percentile(0.50)
				stats.LatencyMsP90 = hist.percentile(0.90)
				stats.LatencyMsP99 = hist.percentile(0.99)
				stats.LatencyMsAvg = hist.avg()
				if opts.summaryJSON {
					enc := json.NewEncoder(os.Stdout)
					enc.SetEscapeHTML(false)
					_ = enc.Encode(stats)
				} else {
					fmt.Fprintf(os.Stdout, "requests=%d success=%d errors=%d bytes=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n", stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.BytesTotal, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
					fmt.Fprintf(os.Stdout, "status: ")
					// 按状态码升序输出，格式 code ===> count
					var codes []int
					for code := range stats.StatusCodes {
						codes = append(codes, code)
					}
					sort.Ints(codes)
					for i, code := range codes {
						if i > 0 {
							fmt.Fprint(os.Stdout, ", ")
						}
						fmt.Fprintf(os.Stdout, "%d ===> %d", code, stats.StatusCodes[code])
					}
					fmt.Fprintln(os.Stdout)
					if !opts.noPretty {
						fmt.Fprintf(os.Stderr, "[summary] concurrency=%d duration=%ds rate=%drps total=%d success=%d errors=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n",
							stats.Concurrency, stats.DurationSec, stats.RatePerSec, stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
					}
				}
				return
			}
			// 非 summary：保留原有逐条结果
			results = make([]jsonResult, total)
			go func() {
				for i := 0; i < total; i++ {
					<-ticker.C
					jobs <- item{idx: i}
				}
				close(jobs)
			}()
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for it := range jobs {
						res := doOnce(client, opts, it.idx, req)
						results[it.idx] = res
					}
				}()
			}
			wg.Wait()
		} else {
			total := opts.repeat
			if total < 1 {
				total = 1
			}
			results = make([]jsonResult, total)
			jobs := make(chan item)
			for w := 0; w < workers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for it := range jobs {
						res := doOnce(client, opts, it.idx, req)
						results[it.idx] = res
					}
				}()
			}
			for i := 0; i < total; i++ {
				jobs <- item{idx: i}
			}
			close(jobs)
			wg.Wait()
		}

		if opts.summaryOnly || opts.summaryJSON {
			stats := summaryStats{Concurrency: workers, DurationSec: opts.durationSec, RatePerSec: opts.ratePerSec, StatusCodes: map[int]int{}}
			hist := newLatencyHist(5, 2000)
			for _, r := range results {
				if r.Error != "" {
					stats.ErrorCount++
					continue
				}
				stats.TotalRequests++
				stats.StatusCodes[r.StatusCode]++
				if r.StatusCode >= 200 && r.StatusCode < 400 {
					stats.SuccessCount++
				} else {
					stats.ErrorCount++
				}
				stats.BytesTotal += int64(r.BodySize)
				if r.Timings != nil {
					hist.add(r.Timings.TotalMs)
				}
			}
			stats.LatencyMsP50 = hist.percentile(0.50)
			stats.LatencyMsP90 = hist.percentile(0.90)
			stats.LatencyMsP99 = hist.percentile(0.99)
			stats.LatencyMsAvg = hist.avg()
			if opts.summaryJSON {
				enc := json.NewEncoder(os.Stdout)
				enc.SetEscapeHTML(false)
				_ = enc.Encode(stats)
			} else {
				fmt.Fprintf(os.Stdout, "requests=%d success=%d errors=%d bytes=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n", stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.BytesTotal, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
				fmt.Fprintf(os.Stdout, "status: ")
				var codes2 []int
				for code := range stats.StatusCodes {
					codes2 = append(codes2, code)
				}
				sort.Ints(codes2)
				for i, code := range codes2 {
					if i > 0 {
						fmt.Fprint(os.Stdout, ", ")
					}
					fmt.Fprintf(os.Stdout, "%d ===> %d", code, stats.StatusCodes[code])
				}
				fmt.Fprintln(os.Stdout)
				if !opts.noPretty {
					fmt.Fprintf(os.Stderr, "[summary] concurrency=%d duration=%ds rate=%drps total=%d success=%d errors=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n",
						stats.Concurrency, stats.DurationSec, stats.RatePerSec, stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
				}
			}
		} else if opts.jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(results); err != nil {
				fmt.Fprintln(os.Stderr, "JSON 输出失败:", err)
				os.Exit(3)
			}
		} else {
			// 并发/多次文件输出模板
			if strings.TrimSpace(opts.outputTemplate) != "" {
				for _, r := range results {
					name := strings.ReplaceAll(opts.outputTemplate, "{index}", fmt.Sprintf("%d", r.Index))
					if opts.outputDir != "" {
						if opts.createDirs {
							_ = os.MkdirAll(opts.outputDir, 0o755)
						}
						name = filepath.Join(opts.outputDir, name)
					}
					f, err := os.Create(name)
					if err != nil {
						fmt.Fprintln(os.Stderr, "创建文件失败:", err)
						os.Exit(3)
					}
					if opts.includeHdr {
						proto := r.Proto
						if proto == "" {
							proto = "HTTP/1.1"
						}
						fmt.Fprintf(f, "%s %s\n", proto, r.Status)
						for k, vs := range r.Headers {
							for _, v := range vs {
								fmt.Fprintf(f, "%s: %s\n", k, v)
							}
						}
						fmt.Fprintln(f)
					}
					if !opts.headOnly {
						if r.Body != "" {
							_, _ = f.Write([]byte(r.Body))
						} else if r.BodyBase64 != "" {
							b, _ := base64.StdEncoding.DecodeString(r.BodyBase64)
							_, _ = f.Write(b)
						}
					}
					f.Close()
					if !opts.noPretty {
						fmt.Fprintf(os.Stderr, "[summary] [%d] method=%s status=%d time=%dms size=%d file=%s url=%s\n", r.Index, r.Method, r.StatusCode, r.Timings.TotalMs, r.BodySize, name, r.URL)
					}
				}
				return
			}
			for _, r := range results {
				ok := "false"
				if r.Matched {
					ok = "true"
				}
				fmt.Fprintf(os.Stdout, "[%d] %s %d %dms matched=%s size=%d\n", r.Index, r.Method, r.StatusCode, r.Timings.TotalMs, ok, r.BodySize)
			}
			// 额外：并发非 summary 的总览摘要（stderr），不影响逐条输出
			if !opts.noPretty {
				stats := summaryStats{Concurrency: workers, DurationSec: opts.durationSec, RatePerSec: opts.ratePerSec, StatusCodes: map[int]int{}}
				hist := newLatencyHist(5, 2000)
				for _, r := range results {
					if r.Error != "" {
						stats.ErrorCount++
						continue
					}
					stats.TotalRequests++
					stats.StatusCodes[r.StatusCode]++
					if r.StatusCode >= 200 && r.StatusCode < 400 {
						stats.SuccessCount++
					} else {
						stats.ErrorCount++
					}
					stats.BytesTotal += int64(r.BodySize)
					if r.Timings != nil {
						hist.add(r.Timings.TotalMs)
					}
				}
				stats.LatencyMsP50 = hist.percentile(0.50)
				stats.LatencyMsP90 = hist.percentile(0.90)
				stats.LatencyMsP99 = hist.percentile(0.99)
				stats.LatencyMsAvg = hist.avg()
				if opts.durationSec > 0 && opts.ratePerSec > 0 {
					fmt.Fprintf(os.Stderr, "[summary] concurrency=%d duration=%ds rate=%drps total=%d success=%d errors=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n",
						stats.Concurrency, stats.DurationSec, stats.RatePerSec, stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
				} else {
					fmt.Fprintf(os.Stderr, "[summary] concurrency=%d total=%d success=%d errors=%d bytes=%d p50=%dms p90=%dms p99=%dms avg=%.1fms\n",
						stats.Concurrency, stats.TotalRequests, stats.SuccessCount, stats.ErrorCount, stats.BytesTotal, stats.LatencyMsP50, stats.LatencyMsP90, stats.LatencyMsP99, stats.LatencyMsAvg)
				}
			}
		}
		if opts.expectString != "" {
			for _, r := range results {
				if !r.Matched {
					os.Exit(22)
				}
			}
		}
		return
	}

	// 单次请求
	res := doOnce(client, opts, 0, req)
	if res.Error != "" {
		fmt.Fprintln(os.Stderr, "请求失败:", res.Error)
		os.Exit(7)
	}

	// --status-only 已移除；请使用 --x-sc

	if opts.traceTimings {
		fmt.Fprintf(os.Stderr, "timings: dns=%dms tcp=%dms tls=%dms ttfb=%dms total=%dms\n", res.Timings.DNSMs, res.Timings.TCPMs, res.Timings.TLSMs, res.Timings.TTFBMs, res.Timings.TotalMs)
	}

	if opts.jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(res); err != nil {
			fmt.Fprintln(os.Stderr, "JSON 输出失败:", err)
			os.Exit(3)
		}
		if opts.expectString != "" && !res.Matched {
			os.Exit(22)
		}
		return
	}

	// 提取快捷输出模式（优先于任何正文/流式输出）
	if opts.xSC || opts.xServer || opts.xCT || opts.xProto || opts.xURL || opts.xLocation || len(opts.xHeaders) > 0 {
		var parts []string
		if opts.xSC {
			parts = append(parts, fmt.Sprintf("%d", res.StatusCode))
		}
		if opts.xProto {
			parts = append(parts, res.Proto)
		}
		if opts.xURL {
			parts = append(parts, res.URL)
		}
		if opts.xServer {
			if v := res.Headers["Server"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		if opts.xCT {
			if v := res.Headers["Content-Type"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		if opts.xLocation {
			if v := res.Headers["Location"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		for _, name := range opts.xHeaders {
			if v := res.Headers[name]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		sep := "\n"
		if opts.xSep != "" {
			sep = opts.xSep
		}
		// 避免默认 stdout 行为在部分终端显示百分号（禁用缓冲态进度影响）
		fmt.Fprint(os.Stdout, strings.Join(parts, sep))
		// 确保换行（若未自定分隔为换行且只一个字段，主动补换行避免终端渲染百分比）
		if !strings.Contains(sep, "\n") {
			fmt.Fprint(os.Stdout, "\n")
		}
		return
	}

	// 输出命名优先级：-o > -J > -O，支持 --output-dir/--create-dirs
	var writer io.Writer = os.Stdout
	var outFile *os.File
	targetName := opts.outputFile
	if targetName == "" {
		if opts.remoteHeaderName {
			if cd, ok := res.Headers["Content-Disposition"]; ok && len(cd) > 0 {
				for _, v := range cd {
					low := strings.ToLower(v)
					if idx := strings.Index(low, "filename="); idx != -1 {
						fn := v[idx+len("filename="):]
						fn = strings.Trim(fn, "\"' ")
						if fn != "" {
							targetName = fn
							break
						}
					}
				}
			}
		}
		if targetName == "" && opts.outputRemoteName {
			base := path.Base(req.URL.Path)
			if base == "/" || base == "." || base == "" {
				base = "index.html"
			}
			targetName = base
		}
	}
	if targetName != "" {
		if opts.outputDir != "" {
			if opts.createDirs {
				_ = os.MkdirAll(opts.outputDir, 0o755)
			}
			targetName = filepath.Join(opts.outputDir, targetName)
		}
		f, err := os.Create(targetName)
		if err != nil {
			fmt.Fprintln(os.Stderr, "创建文件失败:", err)
			os.Exit(3)
		}
		defer f.Close()
		writer = f
		outFile = f
		// Stream to file: lower memory and match on the fly
		res = streamOnce(client, opts, 0, req, writer, opts.expectString)
		if !opts.noPretty {
			fmt.Fprintf(os.Stderr, "[summary] method=%s proto=%s status=%d time=%dms size=%d matched=%v file=%s url=%s\n",
				res.Method, res.Proto, res.StatusCode, res.Timings.TotalMs, res.BodySize, res.Matched, targetName, res.URL)
		}
	}

	// 若未写入文件，且非 JSON 与非 HEAD，仅 stdout 时优先走流式，避免占用内存
	streamedToStdout := false
	if targetName == "" && !opts.jsonOut && !opts.headOnly {
		res = streamOnce(client, opts, 0, req, writer, opts.expectString)
		streamedToStdout = true
		if !opts.noPretty {
			fmt.Fprintf(os.Stderr, "[summary] method=%s proto=%s status=%d time=%dms size=%d matched=%v url=%s\n",
				res.Method, res.Proto, res.StatusCode, res.Timings.TotalMs, res.BodySize, res.Matched, res.URL)
		}
	}

	// -i 或 -I 都应打印响应头
	if (opts.includeHdr || opts.headOnly) && !streamedToStdout {
		// 使用真实协议版本
		proto := res.Proto
		if proto == "" {
			proto = "HTTP/1.1"
		}
		fmt.Fprintf(writer, "%s %s\n", proto, res.Status)
		for k, vs := range res.Headers {
			for _, v := range vs {
				fmt.Fprintf(writer, "%s: %s\n", k, v)
			}
		}
		fmt.Fprintln(writer)
	}

	// 提取快捷输出模式（优先于常规正文输出）
	if opts.xSC || opts.xServer || opts.xCT || opts.xProto || opts.xURL || opts.xLocation || len(opts.xHeaders) > 0 {
		var parts []string
		if opts.xSC {
			parts = append(parts, fmt.Sprintf("%d", res.StatusCode))
		}
		if opts.xProto {
			parts = append(parts, res.Proto)
		}
		if opts.xURL {
			parts = append(parts, res.URL)
		}
		if opts.xServer {
			if v := res.Headers["Server"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		if opts.xCT {
			if v := res.Headers["Content-Type"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		if opts.xLocation {
			if v := res.Headers["Location"]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		for _, name := range opts.xHeaders {
			if v := res.Headers[name]; len(v) > 0 {
				parts = append(parts, v[0])
			} else {
				parts = append(parts, "")
			}
		}
		sep := "\n"
		if opts.xSep != "" {
			sep = opts.xSep
		}
		fmt.Fprint(os.Stdout, strings.Join(parts, sep))
		return
	}

	if opts.headOnly {
		if opts.expectString != "" {
			os.Exit(22)
		}
		return
	}

	var bodyToWrite []byte
	if res.Body != "" {
		bodyToWrite = []byte(res.Body)
	} else if res.BodyBase64 != "" {
		b, _ := base64.StdEncoding.DecodeString(res.BodyBase64)
		bodyToWrite = b
	}
	// -f/--fail: HTTP 错误码时不输出正文（仍已读取以复用连接）
	if opts.failFast && res.StatusCode >= 400 {
		bodyToWrite = nil
	}
	if len(bodyToWrite) > 0 && !streamedToStdout {
		if _, err := writer.Write(bodyToWrite); err != nil {
			fmt.Fprintln(os.Stderr, "写入输出失败:", err)
			os.Exit(3)
		}
	}

	if outFile != nil && opts.verbose {
		fi, _ := outFile.Stat()
		fmt.Fprintf(os.Stderr, "已写入 %s (%d bytes)\n", outFile.Name(), fi.Size())
	}

	if opts.expectString != "" && !res.Matched {
		os.Exit(22)
	}

	if !opts.noPretty && outFile == nil && !streamedToStdout {
		fmt.Fprintf(os.Stderr, "[summary] method=%s proto=%s status=%d time=%dms size=%d matched=%v url=%s\n",
			res.Method, res.Proto, res.StatusCode, res.Timings.TotalMs, res.BodySize, res.Matched, res.URL)
	}

	// -D/--dump-header output
	if opts.dumpHeaderFile != "" {
		if err := func() error {
			f, err := os.Create(opts.dumpHeaderFile)
			if err != nil {
				return err
			}
			defer f.Close()
			proto := res.Proto
			if proto == "" {
				proto = "HTTP/1.1"
			}
			fmt.Fprintf(f, "%s %s\n", proto, res.Status)
			for k, vs := range res.Headers {
				for _, v := range vs {
					fmt.Fprintf(f, "%s: %s\n", k, v)
				}
			}
			return nil
		}(); err != nil {
			fmt.Fprintln(os.Stderr, "写入 header 失败:", err)
		}
	}

	// -w/--write-out tokens
	if strings.TrimSpace(opts.writeOut) != "" {
		out := opts.writeOut
		out = strings.ReplaceAll(out, "%{http_code}", fmt.Sprintf("%d", res.StatusCode))
		out = strings.ReplaceAll(out, "%{response_code}", fmt.Sprintf("%d", res.StatusCode))
		if res.Timings != nil {
			out = strings.ReplaceAll(out, "%{time_total}", fmt.Sprintf("%.3f", float64(res.Timings.TotalMs)/1000.0))
			out = strings.ReplaceAll(out, "%{time_dns}", fmt.Sprintf("%.3f", float64(res.Timings.DNSMs)/1000.0))
			out = strings.ReplaceAll(out, "%{time_tcp}", fmt.Sprintf("%.3f", float64(res.Timings.TCPMs)/1000.0))
			out = strings.ReplaceAll(out, "%{time_tls}", fmt.Sprintf("%.3f", float64(res.Timings.TLSMs)/1000.0))
			out = strings.ReplaceAll(out, "%{time_ttfb}", fmt.Sprintf("%.3f", float64(res.Timings.TTFBMs)/1000.0))
		}
		out = strings.ReplaceAll(out, "%{size_download}", fmt.Sprintf("%d", res.BodySize))
		out = strings.ReplaceAll(out, "%{method}", res.Method)
		out = strings.ReplaceAll(out, "%{proto}", res.Proto)
		out = strings.ReplaceAll(out, "%{url_effective}", res.URL)
		// redirect_url: 从 Location 取第一项
		redir := ""
		if vs, ok := res.Headers["Location"]; ok && len(vs) > 0 {
			redir = vs[0]
		}
		out = strings.ReplaceAll(out, "%{redirect_url}", redir)
		// filename_effective：与单次路径保持一致逻辑（这里只能基于 URL 推断）
		filename := path.Base(res.URL)
		if filename == "/" || filename == "." || filename == "" {
			filename = "index.html"
		}
		out = strings.ReplaceAll(out, "%{filename_effective}", filename)
		// scheme
		scheme := ""
		if u, err := url.Parse(res.URL); err == nil {
			scheme = u.Scheme
		}
		out = strings.ReplaceAll(out, "%{scheme}", scheme)
		// content-type
		ct := ""
		if vs, ok := res.Headers["Content-Type"]; ok && len(vs) > 0 {
			ct = vs[0]
		}
		out = strings.ReplaceAll(out, "%{content_type}", ct)
		fmt.Fprint(os.Stdout, out)
	}
}
