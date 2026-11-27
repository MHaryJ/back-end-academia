package main

import (
	"time"
)

type User struct {
	ID                  uint       `gorm:"primaryKey" json:"-"`
	UUID                string     `gorm:"type:char(36);uniqueIndex;not null" json:"uuid"`
	Name                string     `gorm:"type:varchar(100);not null" json:"name"`
	Username            string     `gorm:"type:varchar(50);uniqueIndex;not null" json:"username"`
	Email               string     `gorm:"type:varchar(150);uniqueIndex;not null" json:"email"`
	PasswordHash        string     `gorm:"type:varchar(255);not null" json:"-"`
	Role                string     `gorm:"type:varchar(30);default:'user';not null" json:"role"`
	IsActive            bool       `gorm:"default:true;not null" json:"is_active"`
	FailedLoginAttempts int        `gorm:"default:0;not null" json:"-"`
	LockedUntil         *time.Time `json:"-"`
	LastLoginAt         *time.Time `json:"last_login_at,omitempty"`
	LastLoginIP         string     `gorm:"type:varchar(45)" json:"-"`
	CreatedAt           time.Time  `json:"created_at"`
	UpdatedAt           time.Time  `json:"updated_at"`
}

type RefreshToken struct {
	ID             uint       `gorm:"primaryKey"`
	UserID         uint       `gorm:"index;not null"`
	User           User       `gorm:"constraint:OnDelete:CASCADE;"`
	TokenHash      string     `gorm:"type:char(64);uniqueIndex;not null"`
	TokenFamily    string     `gorm:"type:char(36);index;not null"`
	IPAddress      string     `gorm:"type:varchar(45)"`
	UserAgent      string     `gorm:"type:varchar(255)"`
	ExpiresAt      time.Time  `gorm:"index;not null"`
	RevokedAt      *time.Time `gorm:"index"`
	ReplacedByHash string     `gorm:"type:char(64)"`
	CreatedAt      time.Time
}

type RevokedToken struct {
	ID        uint      `gorm:"primaryKey"`
	JTI       string    `gorm:"type:char(36);uniqueIndex;not null"`
	ExpiresAt time.Time `gorm:"index;not null"`
	CreatedAt time.Time
}

type SecurityAuditLog struct {
	ID         uint      `gorm:"primaryKey" json:"id"`
	UserID     *uint     `gorm:"index" json:"-"`
	Identifier string    `gorm:"type:varchar(150)" json:"identifier"`
	Event      string    `gorm:"type:varchar(60);index;not null" json:"event"`
	IPAddress  string    `gorm:"type:varchar(45)" json:"ip_address"`
	UserAgent  string    `gorm:"type:varchar(255)" json:"user_agent"`
	Details    string    `gorm:"type:varchar(255)" json:"details"`
	CreatedAt  time.Time `json:"created_at"`
}

type UserResponse struct {
	UUID        string     `json:"uuid"`
	Name        string     `json:"name"`
	Username    string     `json:"username"`
	Email       string     `json:"email"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
}

func (u *User) ToResponse() UserResponse {
	return UserResponse{
		UUID:        u.UUID,
		Name:        u.Name,
		Username:    u.Username,
		Email:       u.Email,
		Role:        u.Role,
		IsActive:    u.IsActive,
		LastLoginAt: u.LastLoginAt,
		CreatedAt:   u.CreatedAt,
	}
}
