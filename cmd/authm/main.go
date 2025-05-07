package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/gin-gonic/gin"
	"github.com/go-co-op/gocron/v2"
	"github.com/rs/zerolog/log"

	"github.com/charleshuang3/authn/internal/config"
	"github.com/charleshuang3/authn/internal/gormw"
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

	// Register OIDC handlers
	oidcProvider := oidc.NewOpenIDProvider(&cfg.OIDC, db)
	oidcProvider.RegisterHandlers(router.Group("/"))

	statisfiles.RegisterHandlers(router.Group("/"))

	// Start server
	addr := fmt.Sprintf(":%d", cfg.Port)
	log.Info().Msgf("Starting server on %s", addr)
	if err := router.Run(addr); err != nil {
		log.Fatal().Err(err).Msg("Failed to start server")
	}
}
