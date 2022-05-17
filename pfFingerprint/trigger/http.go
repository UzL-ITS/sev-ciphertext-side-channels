package trigger

//Construct Triggerer for http/https URIs

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
)

type HTTPTrigger struct {
	url string
}

func (h *HTTPTrigger) Execute() ([]byte, error) {
	resp, err := http.Get(h.url)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed : %v", err)

	}
	//drain http body to wait until server is finished
	body := &bytes.Buffer{}
	if _, err := io.Copy(body, resp.Body); err != nil {
		return nil, fmt.Errorf("Failed do train http response\n")
	}
	if err := resp.Body.Close(); err != nil {
		return nil, fmt.Errorf("Failed to close http response : %v\n", err)
	}

	return body.Bytes(), nil

}

func NewHTTPTrigger(url string) Triggerer {
	return &HTTPTrigger{
		url: url,
	}
}
