package main

import (
	bytebuf "bytes"
	"context"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"time"
)

type ChannelTest struct {
	Phase        string   `json:"phase"`
	GoogleOK     bool     `json:"google_ok"`
	GoogleMS     float64  `json:"google_https_ms"`
	DownloadOK   bool     `json:"download_ok"`
	DownloadMbps float64  `json:"download_mbps"`
	UploadOK     bool     `json:"upload_ok"`
	UploadMbps   float64  `json:"upload_mbps"`
	Errors       []string `json:"errors,omitempty"`
	Finished     string   `json:"finished,omitempty"`
	Next         string   `json:"next_test,omitempty"`
}

func randomTestInterval() time.Duration {
	return 40*time.Second + time.Duration(rand.Int64N(int64(20*time.Second)+1))
}

type speedTargets struct {
	google, download, upload string
	downBytes, upBytes       int64
}

var publicTargets = speedTargets{"https://www.google.com/generate_204", "https://speed.cloudflare.com/__down?bytes=4000000", "https://speed.cloudflare.com/__up", 4_000_000, 1_000_000}

func testChannel(client *http.Client, targets speedTargets, update func(ChannelTest)) ChannelTest {
	s := ChannelTest{Phase: "google"}
	update(s)
	request := func(method, url string, body io.Reader) (*http.Response, time.Duration, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		req, e := http.NewRequestWithContext(ctx, method, url, body)
		if e != nil {
			cancel()
			return nil, 0, e
		}
		req.Header.Set("Cache-Control", "no-store")
		req.Header.Set("Accept-Encoding", "identity")
		if method == "POST" {
			req.Header.Set("Content-Type", "application/octet-stream")
		}
		start := time.Now()
		resp, e := client.Do(req)
		if e != nil {
			cancel()
			return nil, 0, e
		}
		// Cancel only after the caller has finished streaming the body.
		resp.Body = &cancelBody{ReadCloser: resp.Body, cancel: cancel}
		return resp, time.Since(start), nil
	}
	resp, latency, e := request("GET", targets.google, nil)
	if e == nil {
		resp.Body.Close()
		if resp.StatusCode == 204 {
			s.GoogleOK = true
			s.GoogleMS = float64(latency) / float64(time.Millisecond)
		} else {
			e = fmt.Errorf("HTTP %d", resp.StatusCode)
		}
	}
	if e != nil {
		s.Errors = append(s.Errors, "Google: "+e.Error())
	}
	s.Phase = "download"
	update(s)
	resp, _, e = request("GET", targets.download, nil)
	if e == nil {
		if resp.StatusCode != 200 {
			e = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else {
			start := time.Now()
			n, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, targets.downBytes+1))
			elapsed := time.Since(start).Seconds()
			if readErr != nil {
				e = readErr
			} else if n != targets.downBytes {
				e = fmt.Errorf("received %d of %d bytes", n, targets.downBytes)
			} else {
				s.DownloadOK = true
				s.DownloadMbps = float64(n) * 8 / elapsed / 1e6
			}
		}
		resp.Body.Close()
	}
	if e != nil {
		s.Errors = append(s.Errors, "Download: "+e.Error())
	}
	s.Phase = "upload"
	update(s)
	payload := make([]byte, targets.upBytes)
	start := time.Now()
	resp, _, e = request("POST", targets.upload, bytebuf.NewReader(payload))
	if e == nil {
		_, readErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1_000_000))
		resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			e = fmt.Errorf("HTTP %d", resp.StatusCode)
		} else if readErr != nil {
			e = readErr
		} else {
			s.UploadOK = true
			s.UploadMbps = float64(targets.upBytes) * 8 / time.Since(start).Seconds() / 1e6
		}
	}
	if e != nil {
		s.Errors = append(s.Errors, "Upload: "+e.Error())
	}
	s.Phase = "done"
	s.Finished = time.Now().Format(time.RFC3339)
	update(s)
	return s
}

type cancelBody struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (b *cancelBody) Close() error { e := b.ReadCloser.Close(); b.cancel(); return e }
func (c *Collector) setChannelTest(s ChannelTest) {
	c.Lock()
	defer c.Unlock()
	c.state.ChannelTest = s
}
func channelLines(s ChannelTest) (string, string) {
	google := "waiting"
	if s.GoogleOK {
		google = fmt.Sprintf("reachable, HTTPS %.0f ms", s.GoogleMS)
	} else if s.Phase != "" && s.Phase != "google" {
		google = "error"
	}
	down, up := "—", "—"
	if s.DownloadOK {
		down = fmt.Sprintf("%.2f", s.DownloadMbps)
	}
	if s.UploadOK {
		up = fmt.Sprintf("%.2f", s.UploadMbps)
	}
	phase := map[string]string{"": "waiting", "google": "checking Google", "download": "downloading 4 MB", "upload": "uploading 1 MB", "done": "done"}[s.Phase]
	if s.Phase == "done" && len(s.Errors) > 0 {
		phase = "test incomplete"
	}
	next := ""
	if t, e := time.Parse(time.RFC3339, s.Next); e == nil {
		next = " | Next test " + t.Format("15:04:05")
	}
	return "  Google: " + google + next, fmt.Sprintf("  Channel test (Cloudflare): ↓ %s / ↑ %s Mbps — %s", down, up, phase)
}
