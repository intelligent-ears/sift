package httpclient

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"time"
)

// Options holds parameters to customize Sift's HTTP client.
type Options struct {
	Timeout          time.Duration
	UserAgent        string
	MaxRedirects     int
	MaxRetries       int
	RetryDelay       time.Duration
	InsecureSkipVerify bool
}

// Client wraps an http.Client with Sift-specific features.
type Client struct {
	client  *http.Client
	options Options
}

// NewClient builds an HTTP Client using options.
func NewClient(opt Options) *Client {
	if opt.Timeout == 0 {
		opt.Timeout = 15 * time.Second
	}
	if opt.UserAgent == "" {
		opt.UserAgent = "SiftScanner/1.0"
	}
	if opt.MaxRetries == 0 {
		opt.MaxRetries = 3
	}
	if opt.RetryDelay == 0 {
		opt.RetryDelay = 1 * time.Second
	}

	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: opt.InsecureSkipVerify,
		},
	}

	httpClient := &http.Client{
		Timeout: opt.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= opt.MaxRedirects {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	return &Client{
		client:  httpClient,
		options: opt,
	}
}

// Get performs a retry-aware GET request.
func (c *Client) Get(ctx context.Context, urlStr string) (*http.Response, error) {
	return c.DoWithRetry(ctx, "GET", urlStr, nil)
}

// DoWithRetry performs a request, retrying on 429 Too Many Requests or 5xx Server Errors.
func (c *Client) DoWithRetry(ctx context.Context, method, urlStr string, body io.Reader) (*http.Response, error) {
	var lastErr error
	var resp *http.Response

	for attempt := 0; attempt <= c.options.MaxRetries; attempt++ {
		// Respect context cancellation
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		req, err := http.NewRequestWithContext(ctx, method, urlStr, body)
		if err != nil {
			return nil, err
		}

		req.Header.Set("User-Agent", c.options.UserAgent)

		resp, err = c.client.Do(req)
		if err != nil {
			lastErr = err
			c.sleepBeforeRetry(ctx, attempt, nil)
			continue
		}

		// Check rate limits or temporary errors
		if resp.StatusCode == http.StatusTooManyRequests || (resp.StatusCode >= 500 && resp.StatusCode <= 599) {
			lastErr = fmt.Errorf("status code %d", resp.StatusCode)
			c.sleepBeforeRetry(ctx, attempt, resp)
			resp.Body.Close()
			continue
		}

		return resp, nil
	}

	return nil, fmt.Errorf("request failed after %d retries: %w", c.options.MaxRetries, lastErr)
}

func (c *Client) sleepBeforeRetry(ctx context.Context, attempt int, resp *http.Response) {
	if attempt >= c.options.MaxRetries {
		return
	}

	delay := c.options.RetryDelay * time.Duration(1<<attempt) // exponential backoff

	// Check if server specified Retry-After header
	if resp != nil && resp.StatusCode == http.StatusTooManyRequests {
		if retryAfterHeader := resp.Header.Get("Retry-After"); retryAfterHeader != "" {
			if seconds, err := strconv.Atoi(retryAfterHeader); err == nil {
				delay = time.Duration(seconds) * time.Second
			}
		}
	}

	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ctx.Done():
	case <-timer.C:
	}
}

