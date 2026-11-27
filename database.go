package main

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func InitDatabase(cfg Config) *gorm.DB {
	// Ensure target database exists before GORM opens it.
	rootDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.DBUser, cfg.DBPass, cfg.DBHost, cfg.DBPort)

	sqlDB, err := sql.Open("mysql", rootDSN)
	if err != nil {
		log.Fatalf("Gagal membuka koneksi MySQL awal: %v", err)
	}
	createStmt := fmt.Sprintf("CREATE DATABASE IF NOT EXISTS `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci", cfg.DBName)
	if _, err := sqlDB.Exec(createStmt); err != nil {
		_ = sqlDB.Close()
		log.Fatalf("Gagal membuat database %s: %v", cfg.DBName, err)
	}
	_ = sqlDB.Close()

	appDSN := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		cfg.DBUser, cfg.DBPass, cfg.DBHost, cfg.DBPort, cfg.DBName)

	logLevel := logger.Warn
	if cfg.AppEnv == "production" {
		logLevel = logger.Error
	}

	db, err := gorm.Open(mysql.Open(appDSN), &gorm.Config{
		PrepareStmt: true,
		Logger:      logger.Default.LogMode(logLevel),
	})
	if err != nil {
		log.Fatalf("Gagal menghubungkan GORM ke database %s: %v", cfg.DBName, err)
	}

	underlying, err := db.DB()
	if err == nil {
		underlying.SetMaxOpenConns(25)
		underlying.SetMaxIdleConns(10)
		underlying.SetConnMaxLifetime(30 * time.Minute)
	}

	if err := db.AutoMigrate(&User{}, &RefreshToken{}, &RevokedToken{}, &SecurityAuditLog{}); err != nil {
		log.Fatalf("Gagal AutoMigrate database: %v", err)
	}

	return db
}
