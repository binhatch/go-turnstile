package echoturnstile

import (
	"errors"
	"fmt"
	"github.com/binhatch/go-turnstile/turnstile"
	"github.com/labstack/echo/v4"
	echomiddleware "github.com/labstack/echo/v4/middleware"
)

const (
	defaultCloudFlareTurnstileHeaderKey = "cf-turnstile-response"
	defaultCloudFlareRemoteIPHeader     = "CF-Connecting-IP"
)

type middleware struct {
	skipper                        echomiddleware.Skipper
	turnstileVerifier              turnstile.Verifier
	turnstileResponseExtractorFunc TurnstileResponseExtractorFunc
	remoteIPExtractorFunc          RemoteIPExtractorFunc
	idempotencyKeyExtractorFunc    IdempotencyKeyExtractorFunc
}

type Config struct {
	Skipper                        echomiddleware.Skipper
	TurnstileVerifier              turnstile.Verifier
	TurnstileResponseExtractorFunc TurnstileResponseExtractorFunc
	RemoteIPExtractorFunc          RemoteIPExtractorFunc
	IdempotencyKeyExtractorFunc    IdempotencyKeyExtractorFunc
}

func NewMiddleware(secret string) echo.MiddlewareFunc {
	return NewMiddlewareWithConfig(secret, Config{})
}

func NewMiddlewareWithConfig(secret string, cfg Config) echo.MiddlewareFunc {
	var skipper echomiddleware.Skipper
	if cfg.Skipper == nil {
		skipper = echomiddleware.DefaultSkipper
	}

	var turnstileVerifier turnstile.Verifier
	if cfg.TurnstileVerifier == nil {
		turnstileVerifier = turnstile.NewVerifierClient(secret)
	}

	var turnstileResponseExtractorFunc TurnstileResponseExtractorFunc
	if cfg.TurnstileResponseExtractorFunc == nil {
		turnstileResponseExtractorFunc = RequestHeaderTurnstileResponseExtractorFunc()
	}

	var remoteIpExtractorFunc RemoteIPExtractorFunc
	if cfg.RemoteIPExtractorFunc == nil {
		remoteIpExtractorFunc = EchoRemoteIPExtractor
	}

	var idempotencyKeyExtractorFunc IdempotencyKeyExtractorFunc
	if cfg.IdempotencyKeyExtractorFunc == nil {
		idempotencyKeyExtractorFunc = EchoIdempotencyKeyExtractor
	}

	mw := &middleware{
		skipper:                        skipper,
		turnstileVerifier:              turnstileVerifier,
		turnstileResponseExtractorFunc: turnstileResponseExtractorFunc,
		remoteIPExtractorFunc:          remoteIpExtractorFunc,
		idempotencyKeyExtractorFunc:    idempotencyKeyExtractorFunc,
	}

	return mw.Process
}

func (mw *middleware) Process(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		if mw.skipper(c) {
			return next(c)
		}

		turnstileResponseValue, err := mw.turnstileResponseExtractorFunc(c)
		if err != nil {
			return err
		}

		remoteIP, err := mw.remoteIPExtractorFunc(c)
		if err != nil {
			return err
		}

		idempotencyKey, err := mw.idempotencyKeyExtractorFunc(c)
		if err != nil {
			return err
		}

		req := &turnstile.VerificationRequest{
			Response:       turnstileResponseValue,
			RemoteIP:       remoteIP,
			IdempotencyKey: idempotencyKey,
		}

		_, err = mw.turnstileVerifier.Verify(c.Request().Context(), req)
		if err != nil {
			if errors.Is(err, turnstile.ErrValidationFailed) {
				return echo.NewHTTPError(echo.ErrBadRequest.Code, "CloudFlare Turnstile verification failed")
			}

			return err
		}

		return next(c)
	}
}

type TurnstileResponseExtractorFunc func(c echo.Context) (string, error)

type requestHeaderTurnstileResponseExtractor struct {
	headerName string
}

func RequestHeaderTurnstileResponseExtractorFunc() TurnstileResponseExtractorFunc {
	return RequestHeaderTurnstileResponseExtractorFuncWithHeaderName(defaultCloudFlareTurnstileHeaderKey)
}

func RequestHeaderTurnstileResponseExtractorFuncWithHeaderName(headerName string) TurnstileResponseExtractorFunc {
	return (&requestHeaderTurnstileResponseExtractor{headerName: headerName}).Extract
}

func (e *requestHeaderTurnstileResponseExtractor) Extract(c echo.Context) (string, error) {
	val := c.Request().Header.Get(e.headerName)
	if val == "" {
		return "", echo.NewHTTPError(echo.ErrBadRequest.Code,
			fmt.Sprintf("expected turnstile response in header %s", e.headerName))
	}

	return val, nil
}

type RemoteIPExtractorFunc func(c echo.Context) (string, error)

func EchoRemoteIPExtractor(c echo.Context) (string, error) {
	return c.RealIP(), nil
}

type requestHeaderRemoteIPExtractor struct {
	headerName string
}

func (e *requestHeaderRemoteIPExtractor) Extract(c echo.Context) (string, error) {
	val := c.Request().Header.Get(e.headerName)
	if val == "" {
		return "", fmt.Errorf("expected turnstile response in header %s: %w", e.headerName, echo.ErrBadRequest)
	}

	return val, nil
}

func CloudFlareRequestHeaderRemoteIPExtractor() RemoteIPExtractorFunc {
	return (&requestHeaderRemoteIPExtractor{headerName: defaultCloudFlareRemoteIPHeader}).Extract
}

type IdempotencyKeyExtractorFunc func(c echo.Context) (string, error)

func EchoIdempotencyKeyExtractor(c echo.Context) (string, error) {
	requestId := c.Request().Header.Get(echo.HeaderXRequestID)
	if requestId == "" {
		requestId = echomiddleware.DefaultRequestIDConfig.Generator()
	}

	return requestId, nil
}
