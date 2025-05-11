package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"

	"github.com/charleshuang3/authn/internal/gormw"
	"github.com/charleshuang3/authn/internal/handlers/oidc"
)

func TestLoadConfigSuccess(t *testing.T) {
	// Create a temporary directory
	tmpDir := t.TempDir()

	// Create a temporary config file path
	tmpConfigFile := filepath.Join(tmpDir, "config.yaml")

	// Sample valid configuration data
	sampleConfig := &Config{
		Port:    8080,
		GinMode: "debug",
		OIDC: oidc.OIDCProviderConfig{
			Title:         "Test OIDC Provider",
			PrivateKeyPEM: "testprivatekeypem",
			Issuer:        "http://localhost:8080",
			SSO: oidc.SSOConfig{
				Google: oidc.GoogleLogin{
					ClientID:     "testclientid",
					ClientSecret: "testclientsecret",
					RedirectURI:  "http://localhost:8080/callback",
				},
			},
		},
		DB: gormw.Config{
			DSN:                  "testdsn",
			DisableAutomaticPing: false,
			MaxOpenConns:         10,
			MaxIdleConns:         5,
			LogLevel:             2, // gormlog.Error
		},
	}

	// Marshal the sample config to YAML
	configData, err := yaml.Marshal(&sampleConfig)
	assert.NoError(t, err)

	// Write the YAML data to the temporary file
	err = os.WriteFile(tmpConfigFile, configData, 0644)
	assert.NoError(t, err)

	// Load the config from the temporary file
	loadedConfig := LoadConfig(tmpConfigFile)

	// Assert that the loaded config matches the sample config
	assert.NotNil(t, loadedConfig)
	assert.Equal(t, sampleConfig, loadedConfig)
}
