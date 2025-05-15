package middleware

import (
	"slices"
	"time"

	"github.com/charleshuang3/firewall"
	"github.com/charleshuang3/firewall/gcplog"
	"github.com/charleshuang3/firewall/ipgeo"
	"github.com/charleshuang3/firewall/opn"
	"github.com/charleshuang3/firewall/pf"
	"github.com/charleshuang3/firewall/ros"
	"github.com/charleshuang3/firewall/zerolog"
	"github.com/gin-gonic/gin"
	zlog "github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

var (
	logger = log.With().Str("component", "oidc-provider").Logger()
)

type ForgivableError struct {
	DurationInMinute uint `yaml:"duration_in_minute"`
	Count            uint `yaml:"count"`
}

type FirewallConfig struct {
	Provider         string          `yaml:"provider"`
	ProviderIP       string          `yaml:"provider_ip"`
	ProviderUser     string          `yaml:"provider_user"`
	ProviderPassword string          `yaml:"provider_password"`
	ListUUID         string          `yaml:"list_uuid"`
	BanMinutes       uint            `yaml:"ban_minutes"`
	Whitelist        []string        `yaml:"whitelist"`
	Forgivable       ForgivableError `yaml:"forgivable"`

	CityDBFile        string `yaml:"city_db_file"`
	UpdatedCityDBFile string `yaml:"updated_city_db_file"`
	ASNDBFile         string `yaml:"asn_db_file"`
	UpdatedASNDBFile  string `yaml:"updated_asn_db_file"`

	GoogleKeyFile   string `yaml:"google_key_file"`
	GoogleProjectID string `yaml:"google_project_id"`
}

var (
	supportedProviders = []string{"none", "ros", "opn", "pf"}
)

const (
	defaultBanMinutes       = 10
	defaultDurationInMinute = 10
	defaultCount            = 3

	KeyHackingError = "HACKING_ERROR"
)

func (c *FirewallConfig) Validate() {
	if !slices.Contains(supportedProviders, c.Provider) {
		logger.Fatal().Msgf("Provider %s is not supported", c.Provider)
	}

	if c.Provider != "none" {
		if c.ProviderIP == "" {
			logger.Fatal().Msg("ProviderIP is missing")
		}

		if c.ProviderUser == "" {
			logger.Fatal().Msg("ProviderUser is missing")
		}

		if c.ProviderPassword == "" {
			logger.Fatal().Msg("ProviderPassword is missing")
		}

		if c.Provider == "opn" && c.ListUUID == "" {
			logger.Fatal().Msg("ListUUID is missing")
		}
	}

	if c.CityDBFile == "" {
		logger.Fatal().Msg("CityDBFile is missing")
	}

	if c.UpdatedCityDBFile == "" {
		logger.Fatal().Msg("UpdatedCityDBFile is missing")
	}

	if c.ASNDBFile == "" {
		logger.Fatal().Msg("ASNDBFile is missing")
	}

	if c.UpdatedASNDBFile == "" {
		logger.Fatal().Msg("UpdatedASNDBFile is missing")
	}

	c.applyDefault()
}

func (c *FirewallConfig) applyDefault() {
	if c.BanMinutes == 0 {
		c.BanMinutes = defaultBanMinutes
	}

	if c.Forgivable.DurationInMinute == 0 {
		c.Forgivable.DurationInMinute = defaultDurationInMinute
	}

	if c.Forgivable.Count == 0 {
		c.Forgivable.Count = defaultCount
	}
}

type FirewallMiddleware struct {
	fw *firewall.Firewall
}

func NewFirewallMiddleware(conf *FirewallConfig) *FirewallMiddleware {
	var firewallProvider firewall.IFirewall
	switch conf.Provider {
	case "ros":
		firewallProvider = ros.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword)
	case "pf":
		firewallProvider = pf.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword)
	case "opn":
		firewallProvider = opn.New(
			conf.ProviderIP, conf.ProviderUser, conf.ProviderPassword, conf.ListUUID)
	default:
		// keep firewallProvider nil which means no block on firewall
	}

	var fwlogger firewall.ILogger
	if conf.GoogleKeyFile != "" {
		var err error
		fwlogger, err = gcplog.New(conf.GoogleKeyFile, conf.GoogleProjectID, "authn")
		if err != nil {
			logger.Fatal().Err(err).Msg("Failed to create gcp logger")
		}
	} else {
		// fallback to local log if no google key file.
		fwlogger = zerolog.New(logger, zlog.InfoLevel, "authn")
	}

	mm, err := ipgeo.NewAutoUpdateMMIPGeo(
		conf.CityDBFile,
		conf.UpdatedCityDBFile,
		conf.ASNDBFile,
		conf.UpdatedASNDBFile)
	if err != nil {
		logger.Fatal().Err(err).Msg("Failed to create firewall middleware")
	}

	fw := firewall.New(
		conf.Whitelist,
		firewallProvider,
		fwlogger,
		mm,
		firewall.ForgivableError{
			Duration:    time.Duration(conf.Forgivable.DurationInMinute) * time.Minute,
			Count:       int(conf.Forgivable.Count),
			BanInMinute: int(conf.BanMinutes),
		})

	return &FirewallMiddleware{
		fw: fw,
	}
}

func (m *FirewallMiddleware) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// run handle
		c.Next()

		// after handler
		reason, ok := c.Get(KeyHackingError)
		if !ok {
			return
		}

		ip := c.ClientIP()
		m.fw.LogIPError(ip, reason.(string))
	}
}
