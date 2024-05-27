package utils

import (
	"crypto/tls"
	"net/http"
)

var Client = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}