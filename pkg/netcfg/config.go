package netcfg

import "os"

const (
	defaultServerAddr  = ":8080"
	defaultAPIEndpoint = "https://localhost:8080/api"
	defaultRemoteLogURL = "https://localhost:8081/logs"
	defaultRemoteBackupURL = "https://localhost:8081/backups"
	defaultTLSCertFile = "data/certs/server-cert.pem"
	defaultTLSKeyFile  = "data/certs/server-key.pem"
	defaultTLSCAFile   = "data/certs/ca-cert.pem"
)

type Config struct {
	ServerAddr  string
	APIEndpoint string
	RemoteLogURL string
	RemoteBackupURL string
	TLSCertFile string
	TLSKeyFile  string
	TLSCAFile   string
}

func Load() Config {
	return Config{
		ServerAddr:  envOrDefault("SPROUT_SERVER_ADDR", defaultServerAddr),
		APIEndpoint: envOrDefault("SPROUT_API_ENDPOINT", defaultAPIEndpoint),
		RemoteLogURL: envOrDefault("SPROUT_REMOTE_LOG_URL", defaultRemoteLogURL),
		RemoteBackupURL: envOrDefault("SPROUT_REMOTE_BACKUP_URL", defaultRemoteBackupURL),
		TLSCertFile: envOrDefault("SPROUT_TLS_CERT_FILE", defaultTLSCertFile),
		TLSKeyFile:  envOrDefault("SPROUT_TLS_KEY_FILE", defaultTLSKeyFile),
		TLSCAFile:   envOrDefault("SPROUT_TLS_CA_FILE", defaultTLSCAFile),
	}
}

func envOrDefault(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
