package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/caarlos0/env/v9"
	"github.com/joho/godotenv"
	"github.com/zijiren233/rauth/pkg/auth"
	"github.com/zijiren233/rauth/pkg/handler"
	"github.com/zijiren233/rauth/pkg/k8s"
)

type Config struct {
	Port           int           `env:"RAUTH_PORT" envDefault:"8080"`
	Issuer         string        `env:"RAUTH_ISSUER" envDefault:"rauth"`
	Service        string        `env:"RAUTH_SERVICE" envDefault:"registry"`
	SecretName     string        `env:"RAUTH_SECRET_NAME" envDefault:"registry-credentials"`
	PrivateKeyPath string        `env:"RAUTH_PRIVATE_KEY"`
	TokenExpiry    time.Duration `env:"RAUTH_TOKEN_EXPIRY" envDefault:"5m"`
	LogLevel       string        `env:"RAUTH_LOG_LEVEL" envDefault:"info"`
	MockMode       bool          `env:"RAUTH_MOCK_MODE" envDefault:"false"`
	MockConfigPath string        `env:"RAUTH_MOCK_CONFIG"`
}

func main() {
	// Load .env file if exists
	_ = godotenv.Load()

	// Parse config from environment
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse config: %v\n", err)
		os.Exit(1)
	}

	// Setup logger
	logger := setupLogger(cfg.LogLevel)
	logger.Info("starting rauth server",
		"port", cfg.Port,
		"issuer", cfg.Issuer,
		"service", cfg.Service,
		"mockMode", cfg.MockMode)

	// Initialize Kubernetes client (real or mock)
	var k8sClient k8s.ClientInterface
	var err error

	if cfg.MockMode {
		k8sClient, err = initMockClient(cfg, logger)
	} else {
		k8sClient, err = k8s.NewClient(cfg.SecretName)
	}

	if err != nil {
		logger.Error("failed to create kubernetes client", "error", err)
		os.Exit(1)
	}

	if cfg.MockMode {
		logger.Info("using mock kubernetes client")
	} else {
		logger.Info("kubernetes client initialized", "secretName", cfg.SecretName)
	}

	// Load or generate private key
	privateKey, err := loadOrGeneratePrivateKey(cfg.PrivateKeyPath, logger)
	if err != nil {
		logger.Error("failed to load private key", "error", err)
		os.Exit(1)
	}

	// Create token generator
	tokenOption := &auth.TokenOption{
		Issuer:     cfg.Issuer,
		Service:    cfg.Service,
		Expiration: cfg.TokenExpiry,
		PrivateKey: privateKey,
	}
	generator, err := auth.NewTokenGenerator(tokenOption)
	if err != nil {
		logger.Error("failed to create token generator", "error", err)
		os.Exit(1)
	}

	// Create authenticator
	authenticator := auth.NewAuthenticator(k8sClient, generator, logger)

	// Create HTTP handler
	h := handler.NewHandler(authenticator, logger)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/token", h.TokenHandler)
	mux.HandleFunc("/health", h.HealthHandler)
	mux.HandleFunc("/healthz", h.HealthHandler)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		logger.Info("shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()

		if err := server.Shutdown(ctx); err != nil {
			logger.Error("server shutdown error", "error", err)
		}
	}()

	// Start server
	logger.Info("server starting", "addr", server.Addr)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		os.Exit(1)
	}

	logger.Info("server stopped")
}

func initMockClient(cfg *Config, logger *slog.Logger) (k8s.ClientInterface, error) {
	if cfg.MockConfigPath != "" {
		logger.Info("loading mock credentials from config file", "path", cfg.MockConfigPath)
		return k8s.NewMockClientFromConfig(cfg.MockConfigPath)
	}

	logger.Info("loading mock credentials from environment")
	return k8s.NewMockClientFromEnv(), nil
}

func setupLogger(level string) *slog.Logger {
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "warn":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	})
	return slog.New(handler)
}

func loadOrGeneratePrivateKey(path string, logger *slog.Logger) (*rsa.PrivateKey, error) {
	if path == "" {
		logger.Info("no private key path provided, generating new key")
		return nil, nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
		var ok bool
		privateKey, ok = key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
	}

	logger.Info("loaded private key from file", "path", path)
	return privateKey, nil
}
