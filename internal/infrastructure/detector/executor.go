package detector

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

type ExecutorResponse struct {
	Body       string
	StatusCode int
	Headers    http.Header
	Duration   time.Duration
}

type HTTPExecutor struct {
	client  *http.Client
	config  DetectionConfig
}

func NewHTTPExecutor(cfg DetectionConfig) *HTTPExecutor {
	return &HTTPExecutor{
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
		config: cfg,
	}
}

func (e *HTTPExecutor) Execute(ctx context.Context, target string, plugin *Plugin, payload Payload) (*ExecutorResponse, error) {
	payloadValue := payload.Value
	if payload.Encoded {
		payloadValue = EncodePayload(payloadValue)
	}

	reqURL := ResolveTargetPath(target, plugin.Path, payloadValue)

	var bodyReader io.Reader
	if plugin.Body != "" {
		bodyContent := ReplacePlaceholders(plugin.Body, target, payloadValue)
		bodyReader = strings.NewReader(bodyContent)
	}

	req, err := http.NewRequestWithContext(ctx, plugin.Method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range plugin.Headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "SentinelScan-Detector/1.0")
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &ExecutorResponse{
		Body:       string(bodyBytes),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Duration:   duration,
	}, nil
}

func (e *HTTPExecutor) ExecuteBaseline(ctx context.Context, target string, plugin *Plugin) (*ExecutorResponse, error) {
	method := plugin.Method
	path := plugin.Path
	headers := plugin.Headers
	body := plugin.Body

	if plugin.Baseline != nil {
		if plugin.Baseline.Method != "" {
			method = plugin.Baseline.Method
		}
		if plugin.Baseline.Path != "" {
			path = plugin.Baseline.Path
		}
		if plugin.Baseline.Headers != nil {
			headers = plugin.Baseline.Headers
		}
		if plugin.Baseline.Body != "" {
			body = plugin.Baseline.Body
		}
	}

	reqURL := strings.TrimRight(target, "/")
	if strings.HasPrefix(path, "/") {
		reqURL += path
	} else {
		reqURL += "/" + path
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}

	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "SentinelScan-Detector/1.0")
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return &ExecutorResponse{
		Body:       string(bodyBytes),
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Duration:   duration,
	}, nil
}
