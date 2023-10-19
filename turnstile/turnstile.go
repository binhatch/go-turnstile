package turnstile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"
)

const cloudflareTurnstileUrl = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

type turnstileErrorCode string

var (
	missingInputSecret   = turnstileErrorCode("missing-input-secret")
	invalidInputSecret   = turnstileErrorCode("invalid-input-secret")
	missingInputResponse = turnstileErrorCode("missing-input-response")
	invalidInputResponse = turnstileErrorCode("invalid-input-response")
	invalidWidgetID      = turnstileErrorCode("invalid-widget-id")
	invalidParsedSecret  = turnstileErrorCode("invalid-parsed-secret")
	badRequest           = turnstileErrorCode("bad-request")
	timeoutOrDuplicate   = turnstileErrorCode("timeout-or-duplicate")
	internalError        = turnstileErrorCode("internal-error")
)

var (
	ErrInvalidRequest   = errors.New("invalid request")
	ErrValidationFailed = errors.New("response validation failed")
)

type VerificationRequest struct {
	Response       string `json:"response"`
	RemoteIP       string `json:"remoteip"`
	IdempotencyKey string `json:"idempotency_key"`
}

type VerificationResponse struct {
	Success     bool                 `json:"success"`
	ChallengeTs time.Time            `json:"challenge_ts"`
	Hostname    string               `json:"hostname"`
	ErrorCodes  []turnstileErrorCode `json:"error-codes"`
	Action      string               `json:"action"`
	Cdata       string               `json:"cdata"`
}

type Verifier interface {
	Verify(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error)
}

type verifierClient struct {
	secret string
	url    string
}

func NewVerifierClient(secret string) Verifier {
	return &verifierClient{
		secret: secret,
		url:    cloudflareTurnstileUrl,
	}
}

func NewVerifierClientWithURL(secret string, url string) Verifier {
	return &verifierClient{
		secret: secret,
		url:    url,
	}
}

func (t *verifierClient) Verify(ctx context.Context, req *VerificationRequest) (*VerificationResponse, error) {
	requestWithSecret := struct {
		VerificationRequest `json:",inline"`
		Secret              string `json:"secret"`
	}{
		VerificationRequest: *req,
		Secret:              t.secret,
	}

	requestJSON, err := json.Marshal(requestWithSecret)
	if err != nil {
		return nil, fmt.Errorf("can not marshall verification request to JSON: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, t.url, bytes.NewBuffer(requestJSON))
	if err != nil {
		return nil, fmt.Errorf("can not create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	httpResp, err := client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("error sending HTTP request: %w", err)
	}
	defer httpResp.Body.Close()

	resp := &VerificationResponse{}
	if err := json.NewDecoder(httpResp.Body).Decode(resp); err != nil {
		return nil, fmt.Errorf("can not decode turnstile response into JSON: %w", err)
	}

	if !resp.Success {
		return resp, mapErrorCodes(resp.ErrorCodes)
	}

	return resp, nil
}

func mapErrorCodes(codes []turnstileErrorCode) error {
	switch {
	case slices.Contains(codes, internalError):
		return errors.New("turnstile server error")

	case slices.Contains(codes, invalidInputResponse) || slices.Contains(codes, timeoutOrDuplicate):
		return fmt.Errorf("invalid, duplicate or expired response: %v %w", codes, ErrValidationFailed)

	case slices.Contains(codes, badRequest) || slices.Contains(codes, missingInputSecret) ||
		slices.Contains(codes, invalidInputSecret) || slices.Contains(codes, invalidParsedSecret) ||
		slices.Contains(codes, missingInputSecret) || slices.Contains(codes, invalidWidgetID) ||
		slices.Contains(codes, missingInputResponse):
		return fmt.Errorf("validation error(s) on turnstile: %v %w", codes, ErrInvalidRequest)

	default:
		return fmt.Errorf("unhandled turnstile error: %v", codes)
	}
}
