package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestArgon2idHashAndVerify(t *testing.T) {
	hash, err := HashPassword("StrongP@ssword123")
	if err != nil {
		t.Fatalf("expected no error hashing password, got %v", err)
	}

	ok, err := VerifyPassword("StrongP@ssword123", hash)
	if err != nil || !ok {
		t.Fatalf("expected password verification to succeed, ok=%v err=%v", ok, err)
	}

	okWrong, err := VerifyPassword("WrongP@ssword123", hash)
	if err != nil || okWrong {
		t.Fatalf("expected wrong password to fail, ok=%v err=%v", okWrong, err)
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	weak := []string{
		"short1!",
		"alllowercase1!",
		"ALLUPPERCASE1!",
		"NoDigitsHere!",
		"NoSpecialChar123",
	}
	for _, p := range weak {
		if err := ValidatePasswordStrength(p); err == nil {
			t.Errorf("expected weak password %q to fail validation", p)
		}
	}

	if err := ValidatePasswordStrength("ValidP@ssword2026"); err != nil {
		t.Errorf("expected strong password to pass, got %v", err)
	}
}

func TestInternalGatewayMiddlewareBlocksDirectAccessAndReplays(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := Config{
		AppEnv:                "test",
		InternalGatewaySecret: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	nonceStore := NewNonceStore(2 * time.Minute)

	r := gin.New()
	r.Use(InternalGatewayMiddleware(cfg, nonceStore))
	r.POST("/internal/auth/login", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	// 1. Direct request without gateway headers -> 403
	reqNoAuth := httptest.NewRequest(http.MethodPost, "/internal/auth/login", bytes.NewBufferString(`{}`))
	wNoAuth := httptest.NewRecorder()
	r.ServeHTTP(wNoAuth, reqNoAuth)
	if wNoAuth.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without gateway headers, got %d", wNoAuth.Code)
	}

	// 2. Properly signed request -> 200
	body := []byte(`{"identifier":"user@example.com","password":"x"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	nonce := "unique-nonce-value-123456"
	sig := ComputeHMACSignature(cfg.InternalGatewaySecret, http.MethodPost, "/internal/auth/login", ts, nonce, ComputeBodySHA256(body))

	reqSigned := httptest.NewRequest(http.MethodPost, "/internal/auth/login", bytes.NewBuffer(body))
	reqSigned.Header.Set("X-Gateway-Timestamp", ts)
	reqSigned.Header.Set("X-Gateway-Nonce", nonce)
	reqSigned.Header.Set("X-Gateway-Signature", sig)
	wSigned := httptest.NewRecorder()
	r.ServeHTTP(wSigned, reqSigned)
	if wSigned.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid HMAC signature, got %d (%s)", wSigned.Code, wSigned.Body.String())
	}

	// 3. Replaying the exact same nonce -> 403
	reqReplay := httptest.NewRequest(http.MethodPost, "/internal/auth/login", bytes.NewBuffer(body))
	reqReplay.Header.Set("X-Gateway-Timestamp", ts)
	reqReplay.Header.Set("X-Gateway-Nonce", nonce)
	reqReplay.Header.Set("X-Gateway-Signature", sig)
	wReplay := httptest.NewRecorder()
	r.ServeHTTP(wReplay, reqReplay)
	if wReplay.Code != http.StatusForbidden {
		t.Fatalf("expected 403 on nonce replay, got %d", wReplay.Code)
	}
}
