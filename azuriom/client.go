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

func (client *Client) Authenticate(email, password string) (*AuthResponse, error) {
	return client.AuthenticateWith2FA(email, password, "")
}

func (client *Client) AuthenticateWith2FA(email, password, code string) (*AuthResponse, error) {
	payload := map[string]string{
		"email":    email,
		"password": password,
	}
	if code != "" {
		payload["code"] = code
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

		if errResp.Status == "pending" && errResp.Reason == "2fa" {
			return nil, Err2FARequired
		}
		return nil, fmt.Errorf("azuriom: %s - %s", errResp.Reason, errResp.Message)
	}

	var auth AuthResponse
	if err := json.NewDecoder(resp.Body).Decode(&auth); err != nil {
		return nil, fmt.Errorf("azuriom: decode response: %w", err)
	}

	return &auth, nil
}

func (client *Client) Verify(accessToken string) (*AuthResponse, error) {
	payload := map[string]string{
		"access_token": accessToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("azuriom: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, client.URL+path+"verify", bytes.NewReader(body))
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

func (client *Client) Logout(accessToken string) (*AuthResponse, error) {
	payload := map[string]string{
		"access_token": accessToken,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("azuriom: marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, client.URL+path+"logout", bytes.NewReader(body))
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
