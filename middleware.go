package main

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const maxBackendBodyBytes = 1 << 20 // 1 MB

// InternalGatewayMiddleware ensures requests to Backend (:9000) ONLY originate
// from the trusted API Gateway using HMAC-SHA256 + Timestamp + Nonce.
func InternalGatewayMiddleware(cfg Config, nonceStore *NonceStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		ts := strings.TrimSpace(c.GetHeader("X-Gateway-Timestamp"))
		nonce := strings.TrimSpace(c.GetHeader("X-Gateway-Nonce"))
		sig := strings.TrimSpace(c.GetHeader("X-Gateway-Signature"))

		if ts == "" || nonce == "" || sig == "" {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Akses langsung ke backend ditolak: header otentikasi gateway tidak lengkap",
			})
			return
		}

		if !ParseTimestampValid(ts, 60*time.Second) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Akses ditolak: timestamp permintaan kadaluarsa",
			})
			return
		}

		if !nonceStore.CheckAndStore(nonce) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Akses ditolak: nonce tidak valid atau terdeteksi replay attack",
			})
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBackendBodyBytes)
		bodyBytes, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusRequestEntityTooLarge, gin.H{
				"error": "Payload terlalu besar atau tidak terbaca",
			})
			return
		}
		// Restore request body so downstream handlers can bind JSON normally.
		c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		bodyHash := ComputeBodySHA256(bodyBytes)
		if !VerifyHMACSignature(cfg.InternalGatewaySecret, c.Request.Method, c.Request.URL.Path, ts, nonce, bodyHash, sig) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
				"error": "Akses ditolak: signature gateway tidak valid",
			})
			return
		}

		c.Next()
	}
}

func RequireVerifiedUserMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		userUUID := strings.TrimSpace(c.GetHeader("X-Auth-User-UUID"))
		if userUUID == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{
				"error": "Identitas pengguna terverifikasi tidak ditemukan",
			})
			return
		}
		c.Set("auth_user_uuid", userUUID)
		c.Next()
	}
}
