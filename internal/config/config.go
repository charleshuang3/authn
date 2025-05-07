package config

import (
	"os"

	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v2"

	"github.com/charleshuang3/authn/internal/gormw"
	"github.com/charleshuang3/authn/internal/handlers/oidc"
)

var (
	logger = log.With().Str("component", "config").Logger()
)

type Config struct {
	Port    uint                    `yaml:"port"`
	GinMode string                  `yaml:"gin_mode"`
	OIDC    oidc.OIDCProviderConfig `yaml:"oidc"`
	DB      gormw.Config            `yaml:"db"`
}

func LoadConfig(path string) *Config {
	cfg := &Config{}

	file, err := os.Open(path)
	if err != nil {
		logger.Fatal().Err(err).Msgf("failed to open config file: %s", path)
	}
	defer file.Close()

	decoder := yaml.NewDecoder(file)
	if err := decoder.Decode(cfg); err != nil {
		logger.Fatal().Err(err).Msg("failed to decode config file")
	}

	cfg.validate()

	return cfg
}

func (c *Config) validate() {
	if c.Port == 0 {
		logger.Fatal().Msg("Port is missing")
	}

	if c.GinMode == "" {
		logger.Fatal().Msg("GinMode is missing")
	}

	c.OIDC.Validate()
}
