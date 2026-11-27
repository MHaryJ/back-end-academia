package main

import (
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

func SetupRouter(db *gorm.DB, cfg Config, nonceStore *NonceStore, dummyHash string) *gin.Engine {
	if cfg.AppEnv == "production" {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery())

	handler := &BackendHandler{
		DB:        db,
		DummyHash: dummyHash,
	}

	// Health check (does not expose sensitive info)
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "service": "backend"})
	})

	// Zero-trust protection: EVERY auth and business route requires HMAC-signed Gateway headers.
	protected := r.Group("/")
	protected.Use(InternalGatewayMiddleware(cfg, nonceStore))
	{
		internalAuth := protected.Group("/internal/auth")
		{
			internalAuth.POST("/register", handler.Register)
			internalAuth.POST("/login", handler.Login)
			internalAuth.POST("/refresh", handler.Refresh)
			internalAuth.POST("/logout", handler.Logout)
			internalAuth.GET("/revoked/:jti", handler.IsJTIRevoked)
		}

		authedAPI := protected.Group("/")
		authedAPI.Use(RequireVerifiedUserMiddleware())
		{
			authedAPI.GET("/internal/auth/me", handler.Me)
			authedAPI.GET("/api/data", handler.Data)
		}
	}

	return r
}

func main() {
	cfg := LoadConfig()
	db := InitDatabase(cfg)

	dummyHash, err := HashPassword("DummyTimingAttackMitigation!123")
	if err != nil {
		log.Fatalf("Gagal inisialisasi dummy hash: %v", err)
	}

	nonceStore := NewNonceStore(2 * time.Minute)
	router := SetupRouter(db, cfg, nonceStore, dummyHash)

	srv := &http.Server{
		Addr:              cfg.BackendPort,
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("Backend berjalan dengan zero-trust HMAC di %s", cfg.BackendPort)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Backend gagal berjalan: %v", err)
	}
}
