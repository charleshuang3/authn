package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/authn/internal/config"
	"github.com/charleshuang3/authn/internal/gormw"
	"github.com/charleshuang3/authn/internal/handlers/middleware"
	"github.com/charleshuang3/authn/internal/handlers/oidc"
	"github.com/charleshuang3/authn/internal/handlers/statisfiles"
	"github.com/charleshuang3/authn/internal/storage"
)

var (
	configPath = flag.String("c", os.Getenv("CONFIG_PATH"), "Path to configuration file")
)

func main() {
	flag.Parse()
	if *configPath == "" {
		log.Fatal().Msg("Config path must be provided via CONFIG_PATH env var or -c flag")
	}

	// Load configuration
	cfg := config.LoadConfig(*configPath)

	// cron schedule
	scheduler, _ := gocron.NewScheduler()
	scheduler.Start()

	// Initialize database
	db, err := gormw.Open(&cfg.DB)
	if err != nil {
		log.Fatal().Err(err).Msg("Failed to open database")
	}
	if err := db.Migrate(); err != nil {
		log.Fatal().Err(err).Msg("Failed to migrate database")
	}

	storage.RegisterRefreshTokensCleaner(scheduler, db)

	// Set up Gin router
	gin.SetMode(cfg.GinMode)
	router := gin.Default()

	// add firewall middleware
	fw := middleware.NewFirewallMiddleware(&cfg.Firewall)
	router.Use(fw.Middleware())

	// Register OIDC handlers
	oidcProvider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	oidcProvider.RegisterHandlers(router.Group("/"))

	statisfiles.RegisterHandlers(router.Group("/"))

	// Start server
	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
		// Good practice to set timeouts to avoid Slowloris attacks.
		WriteTimeout: time.Second * 15,
		ReadTimeout:  time.Second * 15,
		IdleTimeout:  time.Second * 60,
		Handler:      router,
	}

	// Run our server in a goroutine so that it doesn't block.
	go func() {
		log.Printf("start server at %q", srv.Addr)
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal().Err(err).Msg("Failed to start server")
		}
	}()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	// Create a deadline to wait for.
	wait := time.Second * 15
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	// Doesn't block if no connections, but will otherwise wait
	// until the timeout deadline.
	srv.Shutdown(ctx)

	log.Info().Msg("shutting down")
	os.Exit(0)
}
