package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestChannelMeasuresBothDirections(t *testing.T) {
	uploaded := int64(0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/google":
			w.WriteHeader(204)
		case "/down":
			io.WriteString(w, strings.Repeat("x", 4000))
		case "/up":
			uploaded, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(200)
		}
	}))
	defer server.Close()
	s := testChannel(server.Client(), speedTargets{server.URL + "/google", server.URL + "/down", server.URL + "/up", 4000, 1000}, func(ChannelTest) {})
	if !s.GoogleOK || !s.DownloadOK || !s.UploadOK || uploaded != 1000 || s.DownloadMbps <= 0 || s.UploadMbps <= 0 || s.Phase != "done" {
		t.Fatalf("wrong result: %+v upload=%d", s, uploaded)
	}
}
func TestChannelRejectsTruncatedDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/google" {
			w.WriteHeader(204)
		} else {
			io.WriteString(w, "short")
		}
	}))
	defer server.Close()
	s := testChannel(server.Client(), speedTargets{server.URL + "/google", server.URL + "/down", server.URL + "/up", 4000, 1000}, func(ChannelTest) {})
	if s.DownloadOK || s.DownloadMbps != 0 || len(s.Errors) == 0 {
		t.Fatalf("invalid success: %+v", s)
	}
}
