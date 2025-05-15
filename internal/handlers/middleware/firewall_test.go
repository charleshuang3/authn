package middleware

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFirewallConfig_Validate(t *testing.T) {
	tests := []struct {
		name   string
		config FirewallConfig
	}{
		{
			name: "simple",
			config: FirewallConfig{
				Provider:          "ros",
				ProviderIP:        "192.168.1.1",
				ProviderUser:      "admin",
				ProviderPassword:  "password",
				CityDBFile:        "/path/to/city.mmdb",
				UpdatedCityDBFile: "/path/to/updated_city.mmdb",
				ASNDBFile:         "/path/to/asn.mmdb",
				UpdatedASNDBFile:  "/path/to/updated_asn.mmdb",
			},
		},
		{
			name: "full",
			config: FirewallConfig{
				Provider:         "ros",
				ProviderIP:       "192.168.1.1",
				ProviderUser:     "admin",
				ProviderPassword: "password",
				ListUUID:         "12345",
				Whitelist:        []string{"192.168.1.1", "192.168.1.2"},
				BanMinutes:       10,
				Forgivable: ForgivableError{
					DurationInMinute: 10,
					Count:            3,
				},

				CityDBFile:        "/path/to/city.mmdb",
				UpdatedCityDBFile: "/path/to/updated_city.mmdb",
				ASNDBFile:         "/path/to/asn.mmdb",
				UpdatedASNDBFile:  "/path/to/updated_asn.mmdb",

				GoogleKeyFile:   "/path/to/key.json",
				GoogleProjectID: "project-id",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.Validate()
		})
	}
}

func TestFirewallConfig_applyDefulat(t *testing.T) {
	tests := []struct {
		name           string
		config         FirewallConfig
		expectedConfig FirewallConfig
	}{
		{
			name: "apply defaults when values are zero",
			config: FirewallConfig{
				BanMinutes: 0,
				Forgivable: ForgivableError{
					DurationInMinute: 0,
					Count:            0,
				},
			},
			expectedConfig: FirewallConfig{
				BanMinutes: defaultBanMinutes,
				Forgivable: ForgivableError{
					DurationInMinute: defaultDurationInMinute,
					Count:            defaultCount,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.config.applyDefault()
			assert.Equal(t, tt.expectedConfig, tt.config)
		})
	}
}
