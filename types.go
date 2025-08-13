package main

type multiFlag []string

func (m *multiFlag) String() string {
	return joinStrings(*m, ",")
}

func (m *multiFlag) Set(val string) error {
	*m = append(*m, val)
	return nil
}

type summaryStats struct {
	TotalRequests int         `json:"total_requests"`
	Concurrency   int         `json:"concurrency"`
	DurationSec   int         `json:"duration_sec"`
	RatePerSec    int         `json:"rate_per_sec"`
	SuccessCount  int         `json:"success_count"`
	ErrorCount    int         `json:"error_count"`
	StatusCodes   map[int]int `json:"status_codes"`
	BytesTotal    int64       `json:"bytes_total"`
	LatencyMsP50  int64       `json:"latency_ms_p50"`
	LatencyMsP90  int64       `json:"latency_ms_p90"`
	LatencyMsP99  int64       `json:"latency_ms_p99"`
	LatencyMsAvg  float64     `json:"latency_ms_avg"`
}

// latency histogram with fixed bucket width, approximate percentiles without storing all samples
type latencyHist struct {
	bucketWidthMs int64
	buckets       []int
	overflow      int
	count         int
	sumMs         int64
}

func newLatencyHist(bucketWidthMs int64, numBuckets int) *latencyHist {
	return &latencyHist{bucketWidthMs: bucketWidthMs, buckets: make([]int, numBuckets)}
}

func (h *latencyHist) add(ms int64) {
	h.count++
	h.sumMs += ms
	idx := int(ms / h.bucketWidthMs)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(h.buckets) {
		h.overflow++
		return
	}
	h.buckets[idx]++
}

func (h *latencyHist) percentile(p float64) int64 {
	if h.count == 0 {
		return 0
	}
	rank := int(float64(h.count-1) * p)
	if rank < 0 {
		rank = 0
	}
	cum := 0
	for i, c := range h.buckets {
		cum += c
		if cum > rank {
			return int64(i) * h.bucketWidthMs
		}
	}
	return int64(len(h.buckets)) * h.bucketWidthMs
}

func (h *latencyHist) avg() float64 {
	if h.count == 0 {
		return 0
	}
	return float64(h.sumMs) / float64(h.count)
}
