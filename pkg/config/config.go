package config

import (
	"strings"
	"time"

	"github.com/spf13/viper"
)

// Config holds all configurations for Sift.
type Config struct {
	SubfinderTimeout         time.Duration
	PortScannerPorts         string
	ScanningPacketsPerSecond int
}

var globalConfig Config

func init() {
	Init()
}

// Init initializes configuration defaults and binds environment variables.
func Init() {
	viper.SetEnvPrefix("SIFT")
	viper.AutomaticEnv()
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Defaults
	viper.SetDefault("subfinder.timeout", "60s")
	viper.SetDefault("port_scanner.ports", "21,22,25,80,443,3306,5432,6379,8080,8443")
	viper.SetDefault("scanning.packets_per_second", 5)

	// Bind environment variables explicitly if needed
	_ = viper.BindEnv("subfinder.timeout", "SUBFINDER_TIMEOUT")
	_ = viper.BindEnv("port_scanner.ports", "PORT_SCANNER_PORTS")
	_ = viper.BindEnv("scanning.packets_per_second", "SCANNING_PACKETS_PER_SECOND")

	globalConfig.SubfinderTimeout = viper.GetDuration("subfinder.timeout")
	globalConfig.PortScannerPorts = viper.String("port_scanner.ports")
	globalConfig.ScanningPacketsPerSecond = viper.GetInt("scanning.packets_per_second")
}

// Load loads config from a YAML file path and initializes viper.
func Load(path string) error {
	if path != "" {
		viper.SetConfigFile(path)
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	}
	Init()
	return nil
}

// Get returns the loaded configuration settings.
func Get() Config {
	return globalConfig
}

// ModuleDefaults defines default enablement for all Sift modules.
var ModuleDefaults = map[string]bool{
	"subdomain_enumeration":        true,
	"dns_scanner":                  true,
	"ip_lookup":                    true,
	"port_scanner":                 true,
	"shodan_vulns":                 false,
	"domain_expiration_scanner":    true,
	"dangling_dns_detector":        false,
	"removed_domain_existing_vhost": true,
	"webapp_identifier":            true,
	"wp_scanner":                   true,
	"wordpress_plugins":            true,
	"joomla_scanner":               true,
	"joomla_extensions":            true,
	"drupal_scanner":               true,
	"device_identifier":            true,
	"bruter":                       true,
	"admin_panel_login_bruter":     false,
	"wordpress_bruter":             true,
	"ftp_bruter":                   true,
	"mysql_bruter":                 true,
	"postgresql_bruter":            true,
	"ssh_bruter":                   false,
	"directory_index":              true,
	"robots":                       true,
	"vcs":                          true,
	"scripts_unregistered_domains": true,
	"humble":                       false,
	"api_scanner":                  false,
	"lfi_detector":                 true,
	"smart_nuclei_router":          true,
	"nuclei_module":                true,
	"ssh_bad_keys":                 true,
	"mail_dns_scanner":             true,
	"sql_injection_detector":       true,
	"subdomain_takeover":           true,
	"ssl_scanner":                  true,
	"wpscan":                       false,
	"xss_scanner":                  false,
	"graphql_scanner":              true,
}

// IsModuleEnabled checks if a module is enabled in configuration.
func IsModuleEnabled(name string) bool {
	viperKey := "modules." + name + ".enabled"
	if !viper.IsSet(viperKey) {
		if def, ok := ModuleDefaults[name]; ok {
			return def
		}
		return true
	}
	return viper.GetBool(viperKey)
}

// SetModuleEnabled updates the enablement status of a module and persists config.
func SetModuleEnabled(name string, enabled bool) error {
	viperKey := "modules." + name + ".enabled"
	viper.Set(viperKey, enabled)
	err := viper.WriteConfig()
	if err != nil {
		err = viper.WriteConfigAs("sift.yaml")
		if err != nil {
			return err
		}
	}
	return nil
}

