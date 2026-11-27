package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

const (
	maxFailedAttempts  = 5
	lockoutDuration    = 15 * time.Minute
	refreshTokenExpiry = 7 * 24 * time.Hour
)

type BackendHandler struct {
	DB        *gorm.DB
	DummyHash string
}

type RegisterRequest struct {
	Name     string `json:"name" binding:"required"`
	Username string `json:"username" binding:"required"`
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Identifier string `json:"identifier" binding:"required"`
	Password   string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type LogoutRequest struct {
	RefreshToken   string `json:"refresh_token"`
	AccessJTI      string `json:"access_jti"`
	AccessExpUnix  int64  `json:"access_exp_unix"`
}

func (h *BackendHandler) recordAudit(userID *uint, identifier, event, ip, ua, details string) {
	if len(ua) > 250 {
		ua = ua[:250]
	}
	if len(details) > 250 {
		details = details[:250]
	}
	_ = h.DB.Create(&SecurityAuditLog{
		UserID:     userID,
		Identifier: identifier,
		Event:      event,
		IPAddress:  ip,
		UserAgent:  ua,
		Details:    details,
	}).Error
}

func clientMeta(c *gin.Context) (string, string) {
	ip := strings.TrimSpace(c.GetHeader("X-Forwarded-For"))
	if ip == "" {
		ip = c.ClientIP()
	} else {
		ip = strings.TrimSpace(strings.Split(ip, ",")[0])
	}
	ua := strings.TrimSpace(c.GetHeader("X-Client-User-Agent"))
	if ua == "" {
		ua = c.Request.UserAgent()
	}
	return ip, ua
}

func (h *BackendHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Data registrasi tidak lengkap"})
		return
	}

	name, err := NormalizeName(req.Name)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "field": "name"})
		return
	}
	username, err := NormalizeUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "field": "username"})
		return
	}
	email, err := NormalizeEmail(req.Email)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "field": "email"})
		return
	}
	if err := ValidatePasswordStrength(req.Password); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error(), "field": "password"})
		return
	}

	ip, ua := clientMeta(c)

	var existingCount int64
	h.DB.Model(&User{}).Where("email = ? OR username = ?", email, username).Count(&existingCount)
	if existingCount > 0 {
		var emailExists, usernameExists int64
		h.DB.Model(&User{}).Where("email = ?", email).Count(&emailExists)
		h.DB.Model(&User{}).Where("username = ?", username).Count(&usernameExists)

		if emailExists > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "Email sudah terdaftar", "field": "email"})
			return
		}
		if usernameExists > 0 {
			c.JSON(http.StatusConflict, gin.H{"error": "Username sudah digunakan", "field": "username"})
			return
		}
	}

	pwHash, err := HashPassword(req.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memproses keamanan password"})
		return
	}

	user := User{
		UUID:         uuid.NewString(),
		Name:         name,
		Username:     username,
		Email:        email,
		PasswordHash: pwHash,
		Role:         "user",
		IsActive:     true,
	}

	if err := h.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Email atau username sudah terdaftar"})
		return
	}

	h.recordAudit(&user.ID, user.Email, "REGISTER_SUCCESS", ip, ua, "Akun baru terdaftar dengan Argon2id")

	c.JSON(http.StatusCreated, gin.H{
		"message": "Registrasi berhasil",
		"user":    user.ToResponse(),
	})
}

func (h *BackendHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "Email/username dan password wajib diisi"})
		return
	}

	identifier := strings.ToLower(strings.TrimSpace(req.Identifier))
	ip, ua := clientMeta(c)

	var user User
	err := h.DB.Where("email = ? OR username = ?", identifier, identifier).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			// Constant-time mitigation against user enumeration via timing side-channel.
			_, _ = VerifyPassword(req.Password, h.DummyHash)
			h.recordAudit(nil, identifier, "LOGIN_FAILED", ip, ua, "Akun tidak ditemukan")
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Email/username atau password salah"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Terjadi kesalahan pada server"})
		return
	}

	if !user.IsActive {
		h.recordAudit(&user.ID, user.Email, "LOGIN_BLOCKED_INACTIVE", ip, ua, "Akun dinonaktifkan")
		c.JSON(http.StatusForbidden, gin.H{"error": "Akun Anda dinonaktifkan"})
		return
	}

	now := time.Now()
	if user.LockedUntil != nil && now.Before(*user.LockedUntil) {
		remainingMin := int(user.LockedUntil.Sub(now).Minutes()) + 1
		h.recordAudit(&user.ID, user.Email, "LOGIN_BLOCKED_LOCKED", ip, ua, "Percobaan saat akun terkunci")
		c.JSON(http.StatusLocked, gin.H{
			"error":        fmt.Sprintf("Terlalu banyak percobaan login gagal. Akun dikunci sementara selama %d menit.", remainingMin),
			"locked_until": user.LockedUntil,
		})
		return
	}

	valid, verifyErr := VerifyPassword(req.Password, user.PasswordHash)
	if verifyErr != nil || !valid {
		user.FailedLoginAttempts++
		updates := map[string]any{
			"failed_login_attempts": user.FailedLoginAttempts,
		}
		event := "LOGIN_FAILED"
		msg := "Email/username atau password salah"
		statusCode := http.StatusUnauthorized

		if user.FailedLoginAttempts >= maxFailedAttempts {
			lockUntil := now.Add(lockoutDuration)
			updates["locked_until"] = &lockUntil
			event = "ACCOUNT_LOCKED"
			msg = "Terlalu banyak percobaan login gagal. Akun dikunci selama 15 menit"
			statusCode = http.StatusLocked
		}
		_ = h.DB.Model(&user).Updates(updates).Error
		h.recordAudit(&user.ID, user.Email, event, ip, ua, "Password tidak cocok")

		c.JSON(statusCode, gin.H{"error": msg})
		return
	}

	rawRefresh, err := GenerateRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat sesi token"})
		return
	}

	refreshHash := HashTokenSHA256(rawRefresh)
	family := uuid.NewString()
	refreshExpires := now.Add(refreshTokenExpiry)

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&user).Updates(map[string]any{
			"failed_login_attempts": 0,
			"locked_until":          nil,
			"last_login_at":         &now,
			"last_login_ip":         ip,
		}).Error; err != nil {
			return err
		}

		return tx.Create(&RefreshToken{
			UserID:      user.ID,
			TokenHash:   refreshHash,
			TokenFamily: family,
			IPAddress:   ip,
			UserAgent:   ua,
			ExpiresAt:   refreshExpires,
		}).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan sesi login"})
		return
	}

	h.recordAudit(&user.ID, user.Email, "LOGIN_SUCCESS", ip, ua, "Login berhasil")

	c.JSON(http.StatusOK, gin.H{
		"message":            "Login berhasil",
		"user":               user.ToResponse(),
		"refresh_token":      rawRefresh,
		"refresh_expires_at": refreshExpires.Unix(),
	})
}

func (h *BackendHandler) Refresh(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Refresh token wajib dikirim"})
		return
	}

	ip, ua := clientMeta(c)
	incomingHash := HashTokenSHA256(req.RefreshToken)

	var rt RefreshToken
	if err := h.DB.Preload("User").Where("token_hash = ?", incomingHash).First(&rt).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token tidak valid"})
		return
	}

	now := time.Now()

	// Refresh token reuse / theft detection: revoke entire token family immediately!
	if rt.RevokedAt != nil {
		_ = h.DB.Model(&RefreshToken{}).
			Where("token_family = ? AND revoked_at IS NULL", rt.TokenFamily).
			Update("revoked_at", &now).Error
		h.recordAudit(&rt.UserID, rt.User.Email, "TOKEN_REUSE_DETECTED", ip, ua, "Refresh token bekas dipakai ulang; keluarga token dibekukan")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Sesi dibatalkan karena terdeteksi penggunaan ulang token"})
		return
	}

	if now.After(rt.ExpiresAt) || !rt.User.IsActive {
		_ = h.DB.Model(&rt).Update("revoked_at", &now).Error
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Refresh token sudah kadaluarsa atau akun nonaktif"})
		return
	}

	newRawRefresh, err := GenerateRandomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memutar refresh token"})
		return
	}
	newHash := HashTokenSHA256(newRawRefresh)
	newExp := now.Add(refreshTokenExpiry)

	err = h.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Model(&rt).Updates(map[string]any{
			"revoked_at":       &now,
			"replaced_by_hash": newHash,
		}).Error; err != nil {
			return err
		}

		return tx.Create(&RefreshToken{
			UserID:      rt.UserID,
			TokenHash:   newHash,
			TokenFamily: rt.TokenFamily,
			IPAddress:   ip,
			UserAgent:   ua,
			ExpiresAt:   newExp,
		}).Error
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal memperbarui sesi"})
		return
	}

	h.recordAudit(&rt.UserID, rt.User.Email, "REFRESH_SUCCESS", ip, ua, "Rotasi refresh token berhasil")

	c.JSON(http.StatusOK, gin.H{
		"user":               rt.User.ToResponse(),
		"refresh_token":      newRawRefresh,
		"refresh_expires_at": newExp.Unix(),
	})
}

func (h *BackendHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	_ = c.ShouldBindJSON(&req)

	ip, ua := clientMeta(c)
	now := time.Now()
	var userID *uint
	identifier := c.GetHeader("X-Auth-User-Email")

	if req.RefreshToken != "" {
		hash := HashTokenSHA256(req.RefreshToken)
		var rt RefreshToken
		if err := h.DB.Where("token_hash = ?", hash).First(&rt).Error; err == nil {
			userID = &rt.UserID
			_ = h.DB.Model(&RefreshToken{}).
				Where("token_family = ? AND revoked_at IS NULL", rt.TokenFamily).
				Update("revoked_at", &now).Error
		}
	}

	if req.AccessJTI != "" {
		exp := now.Add(30 * time.Minute)
		if req.AccessExpUnix > now.Unix() {
			exp = time.Unix(req.AccessExpUnix, 0)
		}
		_ = h.DB.Where(RevokedToken{JTI: req.AccessJTI}).
			FirstOrCreate(&RevokedToken{
				JTI:       req.AccessJTI,
				ExpiresAt: exp,
			}).Error
	}

	h.recordAudit(userID, identifier, "LOGOUT", ip, ua, "Sesi logout & token dicabut")
	c.JSON(http.StatusOK, gin.H{"message": "Logout berhasil"})
}

func (h *BackendHandler) IsJTIRevoked(c *gin.Context) {
	jti := strings.TrimSpace(c.Param("jti"))
	if jti == "" {
		c.JSON(http.StatusBadRequest, gin.H{"revoked": true})
		return
	}
	var count int64
	h.DB.Model(&RevokedToken{}).Where("jti = ? AND expires_at > ?", jti, time.Now()).Count(&count)
	c.JSON(http.StatusOK, gin.H{"revoked": count > 0})
}

func (h *BackendHandler) Me(c *gin.Context) {
	userUUID := c.GetString("auth_user_uuid")
	var user User
	if err := h.DB.Where("uuid = ? AND is_active = ?", userUUID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Pengguna tidak ditemukan atau tidak aktif"})
		return
	}

	var recentLogs []SecurityAuditLog
	h.DB.Where("user_id = ?", user.ID).Order("id desc").Limit(5).Find(&recentLogs)

	c.JSON(http.StatusOK, gin.H{
		"user":        user.ToResponse(),
		"audit_logs":  recentLogs,
	})
}

func (h *BackendHandler) Data(c *gin.Context) {
	userUUID := c.GetString("auth_user_uuid")
	var user User
	if err := h.DB.Where("uuid = ? AND is_active = ?", userUUID, true).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Pengguna tidak valid"})
		return
	}

	var recentLogs []SecurityAuditLog
	h.DB.Where("user_id = ?", user.ID).Order("id desc").Limit(5).Find(&recentLogs)

	c.JSON(http.StatusOK, gin.H{
		"message":            "Data aman dari Backend Golang (Terverifikasi JWT + HMAC Gateway)",
		"authenticated_user": user.ToResponse(),
		"security_status": gin.H{
			"password_hash_algo": "Argon2id",
			"gateway_hmac":       "verified",
			"token_jti":          c.GetHeader("X-Auth-Token-JTI"),
		},
		"recent_audit_logs": recentLogs,
	})
}
