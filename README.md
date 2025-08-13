# curl-go

用 Go 实现的轻量 `curl` 替代工具，专注易用、高性能、低内存占用，支持常用 `curl` 参数与压测能力。

## 安装

```bash
go build -o curl-go
```

或者直接使用本地构建产物：`./curl-go`

## 快速开始

```bash
# 最简单的请求
./curl-go https://httpbin.org/get

# 指定方法、头和 Body
./curl-go -X POST -H "Content-Type: application/json" --json '{"a":1}' https://httpbin.org/post

# 仅输出状态码
./curl-go --x-sc https://httpbin.org/status/201

# 跟随重定向并打印响应头
./curl-go -L -i http://httpbin.org/redirect-to?url=https://example.com

# 以 JSON 输出结果
./curl-go --json-out https://httpbin.org/get

# 并发压测（每秒 50 个请求、持续 10 秒，仅摘要）
./curl-go --duration 10 --rate 50 --summary https://httpbin.org/get

# 将响应落盘
./curl-go -o out.html https://example.com

# 并发落盘（每条独立文件），Index 占位
./curl-go --concurrency 5 --repeat 20 \
  --output-template out-{index}.bin https://httpbin.org/bytes/256
```

## 功能特性

- HTTP 方法：GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS（`-X`）
- 头部：`-H` 可重复
- Body：`-d`、`--json`、`--data-urlencode`、`-F`（multipart）
- URL 查询：`-G` 与 `--url-query`
- Cookie：`-b` 设置、`-c/--cookie-jar` 持久化
- 代理：`--proxy`/`-x`
- 超时：`-m`（整体）、`--connect-timeout`（连接阶段）
- 重定向：`-L` 与 `--max-redirs`
- TLS：`-k` 跳过校验
- HTTP 版本：`--http1.0` / `--http1.1` / `--http2`
- Range：`-r/--range`
- 失败不输出正文：`-f/--fail`
- 重试：`--retry`、`--retry-delay`、`--retry-max-time`
- 输出：`-i`（包含响应头）、`-o`/`-O`/`-J`、`--output-dir`、`--create-dirs`
- 并发/压测：`--concurrency`、`--repeat`、`--duration`、`--rate`、`--summary`、`--summary-json`
- 匹配：`--expect-string`（正文包含检测）
- 压缩：`--compressed`（请求 gzip）/`--raw`（返回原始压缩体）
- JSON 输出：`--json-out`，可配 `--json-body-plain`
- 耗时追踪：`--trace`（DNS/TCP/TLS/TTFB/Total）
- UA：`-A` 自定义
- Write-out：`-w/--write-out` 支持占位（见下）
- 多语言帮助：`--help-lang zh|en`
- 精简摘要：`--pretty`/`--no-pretty`
- 并发落盘模板：`--output-template out-{index}.bin`
- 快速提取：`--x-sc`（状态码）、`--x-server`、`--x-ct`、`--x-proto`、`--x-url`、`--x-loc`、`--x-header Name`、`--x-sep SEP`

## Write-out 占位符

支持（不完全列表）：

- `%{http_code}` / `%{response_code}`
- `%{time_total}` `%{time_dns}` `%{time_tcp}` `%{time_tls}` `%{time_ttfb}`（单位：秒，保留 3 位小数）
- `%{size_download}`
- `%{method}` `%{proto}` `%{url_effective}` `%{content_type}`
- `%{redirect_url}`（若存在 `Location`）
- `%{filename_effective}`（基于 URL 推断）
- `%{scheme}`（http/https）

示例：

```bash
./curl-go -w "code=%{http_code} proto=%{proto} total=%{time_total}s ttfb=%{time_ttfb}s\n" https://example.com
```

## 压测与并发

- 定速压测：`--duration` 配合 `--rate`，可选 `--summary`/`--summary-json` 输出总览
- 并发多次：`--concurrency` + `--repeat`
- 内存优化：摘要模式下使用固定桶直方图估分位，不存储全部样本；非摘要下也提供简要 stderr 总览
- 连接复用：自动丢弃不需要的响应体以保持连接池健康
- 建议：压测时默认 `--no-jar` + `--no-body`（可被显式覆盖）

## 输出与落盘

- 单次请求：
  - `-o` 指定文件
  - `-O` 使用远端名
  - `-J` 使用 `Content-Disposition`
  - `--output-dir` / `--create-dirs`
- 并发/多次：
  - `--output-template` 按 `{index}` 生成多个文件，可与 `--output-dir` 组合

## 多语言帮助

```bash
./curl-go --help-lang en --help
./curl-go --help-lang zh --help
```

## 开发与测试

```bash
go build -o curl-go
go test ./...
```

## 设计与性能

- 采用 `http.Transport` 调优：`MaxIdleConns`/`MaxIdleConnsPerHost`/`IdleConnTimeout`
- 流式输出：文件与 stdout 在单次请求路径走边写边匹配，避免大内存峰值
- 复用请求体：为可重试的请求设置 `GetBody`
- 直方图统计：压测摘要无需保存全部样本
