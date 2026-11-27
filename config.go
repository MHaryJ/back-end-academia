package main

import (
	"bufio"
	"log"
	"os"
	"strings"
)

type Config struct {
	AppEnv                string
	BackendPort           string
	DBHost                string
	DBPort                string
	DBUser                string
	DBPass                string
	DBName                string
	InternalGatewaySecret string
}

func loadDotEnv(path string) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		val = strings.Trim(val, `"'`)
		if _, exists := os.LookupEnv(key); !exists {
			_ = os.Setenv(key, val)
		}
	}
}

func getEnvOrDefault(key, fallback string) string {
	if val := strings.TrimSpace(os.Getenv(key)); val != "" {
		return val
	}
	return fallback
}

func LoadConfig() Config {
	loadDotEnv(".env")

	cfg := Config{
		AppEnv:                getEnvOrDefault("APP_ENV", "local"),
		BackendPort:           getEnvOrDefault("BACKEND_PORT", ":9000"),
		DBHost:                getEnvOrDefault("DB_HOST", "127.0.0.1"),
		DBPort:                getEnvOrDefault("DB_PORT", "3306"),
		DBUser:                getEnvOrDefault("DB_USER", "root"),
		DBPass:                os.Getenv("DB_PASS"),
		DBName:                getEnvOrDefault("DB_NAME", "loading_board"),
		InternalGatewaySecret: strings.TrimSpace(os.Getenv("INTERNAL_GATEWAY_SECRET")),
	}

	if cfg.InternalGatewaySecret == "" || len(cfg.InternalGatewaySecret) < 32 {
		log.Fatal("FATAL: INTERNAL_GATEWAY_SECRET wajib diisi minimal 32 karakter pada backend/.env")
	}

	return cfg
}
