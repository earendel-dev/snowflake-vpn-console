package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCountryWarningsAreRed(t *testing.T) {
	s := compareCountries(geoReply{IP: "192.0.2.1", Country: "US"}, geoReply{IP: "198.51.100.1", Country: "US"})
	if !s.SameCountry || s.SameIP || !strings.Contains(countryLine(s), "\x1b[1;31m") {
		t.Fatal(s)
	}
	s = compareCountries(geoReply{IP: "192.0.2.1", Country: "US"}, geoReply{IP: "192.0.2.1", Country: "US"})
	if !s.SameIP || !strings.Contains(countryLine(s), "IDENTICAL") {
		t.Fatal(s)
	}
	s = compareCountries(geoReply{IP: "192.0.2.1", Country: "US"}, geoReply{IP: "198.51.100.1", Country: "DE"})
	if s.SameCountry || strings.Contains(countryLine(s), "WARNING") {
		t.Fatal(s)
	}
}
func TestCountryLookupRejectsInvalidData(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"success":true,"ip":"invalid","country_code":"US"}`))
	}))
	defer server.Close()
	if _, e := lookupCountry(server.Client(), server.URL); e == nil {
		t.Fatal("invalid IP accepted")
	}
}
