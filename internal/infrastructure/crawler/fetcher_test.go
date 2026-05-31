package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFetcher_Fetch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "SentinelScan-Crawler/1.0", r.UserAgent())
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "Hello, World!")
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{
		Timeout:   5 * time.Second,
		UserAgent: "SentinelScan-Crawler/1.0",
	})

	result, err := fetcher.Fetch(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
	assert.Equal(t, "Hello, World!", result.Body)
}

func TestFetcher_Fetch_Non200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Not Found")
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	result, err := fetcher.Fetch(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, 404, result.StatusCode)
}

func TestFetcher_FetchHEAD(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodHead, r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	status, err := fetcher.FetchHEAD(context.Background(), server.URL)
	require.NoError(t, err)
	assert.Equal(t, 200, status)
}

func TestFetcher_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 10 * time.Millisecond})
	_, err := fetcher.Fetch(context.Background(), server.URL)
	assert.Error(t, err)
}

func TestFetcher_Redirect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/target", http.StatusMovedPermanently)
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "Target")
		}
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	result, err := fetcher.Fetch(context.Background(), server.URL+"/redirect")
	require.NoError(t, err)
	assert.Equal(t, 200, result.StatusCode)
	assert.Equal(t, "Target", result.Body)
}

func TestFetcher_CustomHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer token123", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{
		Timeout: 5 * time.Second,
		Headers: map[string]string{"Authorization": "Bearer token123"},
	})
	_, err := fetcher.Fetch(context.Background(), server.URL)
	require.NoError(t, err)
}

func TestFetcher_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := fetcher.Fetch(ctx, server.URL)
	assert.Error(t, err)
}

func TestFetcher_Close(t *testing.T) {
	fetcher := NewFetcher(FetcherConfig{RateLimit: 10 * time.Millisecond})
	fetcher.Close()
}
