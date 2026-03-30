package azuriom

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

var path string = "/api/auth/"

type Client struct {
	URL        string
	httpClient *http.Client
}

func NewClient(url string) *Client {
	return &Client{
		URL:        url,
		httpClient: &http.Client{},
	}
}

func (client *Client) Verify(username, password string) (*AuthResponse, error) {
	payload := map[string]string{
		"email":    username,
		"password": password,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("azuriom: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, client.URL+path+"authenticate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("azuriom: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("azuriom: do request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var errResp ErrorResponse
		if err := json.NewDecoder(resp.Body).Decode(&errResp); err != nil {
			return nil, fmt.Errorf("azuriom: status %d", resp.StatusCode)
		}
		return nil, fmt.Errorf("azuriom: %s - %s", errResp.Reason, errResp.Message)
	}

	var auth AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("azuriom: decode response: %w", err)
	}

	return &auth, nil
}
