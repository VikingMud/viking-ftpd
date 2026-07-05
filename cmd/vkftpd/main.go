package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/mmcdole/viking-ftpd/pkg/authentication"
	"github.com/mmcdole/viking-ftpd/pkg/authorization"
	"github.com/mmcdole/viking-ftpd/pkg/ftpserver"
	"github.com/mmcdole/viking-ftpd/pkg/logging"
	"github.com/mmcdole/viking-ftpd/pkg/status"
	"github.com/mmcdole/viking-ftpd/pkg/users"
	"github.com/spf13/cobra"
)

var (
	version     = "dev" // Will be set during build
	cfgFile     string
	showVersion bool
)

func main() {
	cobra.CheckErr(rootCmd.Execute())
}

var rootCmd = &cobra.Command{
	Use:           "vkftpd",
	Short:         "VikingMUD FTP Server",
	SilenceUsage:  false,
	SilenceErrors: true,
	Long: `VikingMUD FTP Server (vkftpd) - Secure FTP access to VikingMUD

This server integrates with VikingMUD's authentication and access control systems,
providing secure FTP access while respecting the MUD's permissions system.

Configuration file must be in JSON format with the following structure:
{
    "listen_addr": "0.0.0.0",
    "port": 2121,
    "max_connections": 10,
    "idle_timeout": 300,
    "ftp_root_dir": "/mud/lib",
    "home_pattern": "players/%s",
    "pasv_port_range": [2122, 2150],
    "pasv_address": "",
    "pasv_ip_verify": false,
    "tls_cert_file": "/path/to/cert.pem",
    "tls_key_file": "/path/to/key.pem",
    "character_dir_path": "/mud/lib/characters",
    "access_file_path": "/mud/lib/dgd/sys/data/access.o",
    "character_cache_time": 60,
    "access_cache_time": 60,
    "access_log_path": "/mud/lib/log/vkftpd-access.log",
    "app_log_path": "/mud/lib/log/vkftpd-app.log",
    "log_level": "info"
}`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if showVersion {
			fmt.Printf("VikingMUD FTP Server %s\n", version)
			return nil
		}

		if cfgFile == "" {
			return fmt.Errorf("config file is required (use --config)")
		}

		// Convert to absolute path if needed
		if !filepath.IsAbs(cfgFile) {
			var err error
			cfgFile, err = filepath.Abs(cfgFile)
			if err != nil {
				return fmt.Errorf("failed to get absolute path: %w", err)
			}
		}

		// Load configuration
		var config Config
		if err := LoadConfig(cfgFile, &config); err != nil {
			return fmt.Errorf("failed to load config: %w", err)
		}

		// Initialize logging
		if err := logging.Initialize(
			config.AccessLogPath,
			config.AppLogPath,
			logging.LogLevel(config.LogLevel),
			int64(config.MaxLogSize),
			time.Duration(config.LogVerifyInterval)*time.Second,
		); err != nil {
			return fmt.Errorf("failed to initialize logging: %w", err)
		}
		defer logging.Shutdown()

		// Create user source
		charSource := users.NewFileSource(config.CharacterDirPath)

		// Create authenticator
		// Use a multi-hash verifier that supports both legacy unixcrypt and argon2id
		authenticator := authentication.NewAuthenticator(charSource, authentication.NewVerifier())

		// Create authorizer for permission checks
		accessSource := authorization.NewAccessFileSource(config.AccessFilePath)
		authorizer := authorization.NewAuthorizer(accessSource, charSource, time.Duration(config.AccessCacheTime)*time.Second)

		// Create and start FTP server
		server, err := ftpserver.New(&ftpserver.Config{
			ListenAddr:    config.ListenAddr,
			Port:          config.Port,
			RootDir:       config.FTPRootDir,
			HomePattern:   config.HomePattern,
			TLSCertFile:   config.TLSCertFile,
			TLSKeyFile:    config.TLSKeyFile,
			PasvPortRange: config.PasvPortRange,
			PasvAddress:   config.PasvAddress,
			PasvIPVerify:  config.PasvIPVerify,
			IdleTimeout:   config.IdleTimeout,
		}, authorizer, authenticator, version)
		if err != nil {
			return fmt.Errorf("failed to create FTP server: %w", err)
		}

		// Initialize status writer if configured
		var statusWriter *status.Writer
		if config.StatusDir != "" {
			statusWriter, err = status.New(config.StatusDir, 10*time.Second, version)
			if err != nil {
				return fmt.Errorf("failed to create status writer: %w", err)
			}

			statusWriter.SetMetricsProvider(server)

			if err := statusWriter.WriteStartFile(); err != nil {
				return fmt.Errorf("failed to write start file: %w", err)
			}

			statusWriter.StartHeartbeat()

			// Fallback for panics and unexpected exits
			defer statusWriter.Shutdown("unexpected_exit")
		}

		logging.App.Info("Starting VikingMUD FTP Server", "version", version, "listen_addr", config.ListenAddr, "port", config.Port)

		// Set up signal handling for graceful shutdown
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

		// Start server in goroutine
		serverErr := make(chan error, 1)
		go func() {
			serverErr <- server.ListenAndServe()
		}()

		// Wait for signal or server error
		select {
		case err := <-serverErr:
			if statusWriter != nil {
				reason := "server_stopped"
				if err != nil {
					reason = "server_error"
				}
				statusWriter.Shutdown(reason)
			}

			if err != nil {
				logging.App.Error("Server error", "error", err)
				return fmt.Errorf("server error: %w", err)
			}

		case sig := <-sigChan:
			logging.App.Info("Received signal, shutting down gracefully", "signal", sig)

			if statusWriter != nil {
				statusWriter.Shutdown(fmt.Sprintf("signal_%s", sig))
			}

			// Create a context with timeout for graceful shutdown
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			// Stop accepting new connections and wait for existing ones
			if err := server.Stop(); err != nil {
				logging.App.Error("Error stopping server", "error", err)
				return fmt.Errorf("error stopping server: %w", err)
			}

			// Wait a bit for connections to clean up
			select {
			case <-ctx.Done():
				logging.App.Warn("Shutdown timeout exceeded, forcing exit")
			case <-time.After(2 * time.Second):
				logging.App.Info("Graceful shutdown complete")
			}
		}

		return nil
	},
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file path")
	rootCmd.PersistentFlags().BoolVarP(&showVersion, "version", "v", false, "show version")
}
