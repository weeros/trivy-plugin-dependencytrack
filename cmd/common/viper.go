package common

import (
	"fmt"
	"os"
)

//goland:noinspection GoCommentStart
const (
	VEnvPrefix         = "TRIVY_PLUGIN_DEPENDENCYTRACK"
	VDefaultConfigName = ".trivy_plugin_dependencytrack"

	// Root config keys

	VConfig        = "config"
	VConfigLong    = "config"
	VConfigShort   = "c"
	VConfigDefault = ""
	VConfigUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_CONFIG
Optional config file (default $HOME/.trivy_plugin_dependencytrack.yaml)`

	VLogLevel        = "log-level"
	VLogLevelLong    = "log-level"
	VLogLevelShort   = "l"
	VLogLevelDefault = "info"
	VLogLevelUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_LOG_LEVEL
CfgFile: log-level
Log level [debug, info, warn, error]`

	VLogFormat        = "log-format"
	VLogFormatLong    = "log-format"
	VLogFormatDefault = "console"
	VLogFormatUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_LOG_FORMAT
CfgFile: log-format
Log format [console, json, dev, none]`


	VNoColor        = "no-color"
	VNoColorLong    = "no-color"
	VNoColorDefault = false
	VNoColorUsage   = `Env: TRIVY_PLUGIN_ZARF_NO_COLOR
CfgFile: no-color
Disable colorized output`


	VUrl        = "url"
	VUrlLong    = "url"
	VUrlDefault = "http://localhost:8081"
	VUrlUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_URL
CfgFile: url
DependencyTrack URL`

	VApiKey        = "apikey"
	VApiKeyLong    = "apikey"
	VApiKeyDefault = ""
	VApiKeyUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_APIKEY
CfgFile: apikey
DependencyTrack API Key`

	VProjectName        = "project-name"
	VProjectNameLong    = "project-name"
	VProjectNameDefault = ""
	VProjectNameUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_PROJECT_NAME
CfgFile: project-name
DependencyTrack Project Name`

	VProjectVersion        = "project-version"
	VProjectVersionLong    = "project-version"
	VProjectVersionDefault = ""
	VProjectVersionUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_PROJECT_VERSION
CfgFile: project-version
DependencyTrack Project Version`

	VAutoCreate        = "auto-create"
	VAutoCreateLong    = "auto-create"
	VAutoCreateDefault = true
	VAutoCreateUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_AUTOCREATE
CfgFile: auto-create
Auto-create project if it doesn't exist`

	VBomFile        = "bom-file"
	VBomFileLong    = "bom-file"
	VBomFileDefault = ""
	VBomFileUsage   = `Env: TRIVY_PLUGIN_DEPENDENCYTRACK_BOM_FILE
CfgFile: bom-file
DependencyTrack BOM File`
)

func ValidateConfig(configPath string) error {
	if configPath == "" {
		return fmt.Errorf("config path cannot be empty")
	}
	// Check if the file exists
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", configPath)
	}

	return nil
}
