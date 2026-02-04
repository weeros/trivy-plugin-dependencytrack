package cmd

import (
	"os"

	"github.com/weeros/trivy-plugin-dependencytrack/cmd/common"
	"github.com/weeros/trivy-plugin-dependencytrack/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

)

func NewUploadGitlabCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "upload-gitlab [flags]",
		Short:         "Upload a DependencyTrack package",
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			urlApi := viper.GetString(common.VUrlApi)
			apikey := viper.GetString(common.VApiKey)
			AutoCreate := viper.GetBool(common.VAutoCreate)
			BomFile := viper.GetString(common.VBomFile)
			gitlabBranch := viper.GetBool(common.VGitlabBranch)
			gitlabTag := viper.GetBool(common.VGitlabTag)
			gitlabMR := viper.GetBool(common.VGitlabMR)
			err := upload(urlApi, apikey, "", "", AutoCreate, BomFile, gitlabBranch, gitlabTag, gitlabMR, true)
			if err != nil {
				logger.Default().Error("Error uploading DependencyTrack sbom", "error", err)
				return err
			}
			return nil
		},
		Example: `
# Upload a local dependencytrack sbom in GitLab CI context:
trivy dependencytrack upload-gitlab
`,
	}

	cmd.Flags().String(common.VUrlApi, common.VUrlApiDefault, common.VUrlApiUsage)
	err := viper.BindPFlag(common.VUrlApi, cmd.Flags().Lookup(common.VUrlApiLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}


	cmd.Flags().String(common.VProjectName, common.VProjectNameDefault, common.VProjectNameUsage)
	err = viper.BindPFlag(common.VProjectName, cmd.Flags().Lookup(common.VProjectNameLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().String(common.VProjectVersion, common.VProjectVersionDefault, common.VProjectVersionUsage)
	err = viper.BindPFlag(common.VProjectVersion, cmd.Flags().Lookup(common.VProjectVersionLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().Bool(common.VAutoCreate, common.VAutoCreateDefault, common.VAutoCreateUsage)
	err = viper.BindPFlag(common.VAutoCreate, cmd.Flags().Lookup(common.VAutoCreateLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().String(common.VBomFile, common.VBomFileDefault, common.VBomFileUsage)
	err = viper.BindPFlag(common.VBomFile, cmd.Flags().Lookup(common.VBomFileLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}


	return cmd
}




func gitlabGenerateProjectInfo(projectName, projectVersion string, gitlabBranch, gitlabTag, gitlabMR bool) (string, string) {

	if os.Getenv("CI_MERGE_REQUEST_IID") != "" && gitlabMR == false {
		logger.Default().Info("Running in GitLab Merge Request context")
		return	"", ""
	}

	if os.Getenv("CI_COMMIT_BRANCH") != "" && gitlabBranch == false {
		logger.Default().Info("Running in GitLab Branch context")
		return "", ""
	}
	
	if os.Getenv("CI_COMMIT_TAG") != "" && gitlabTag == false {
		logger.Default().Info("Running in GitLab Tag context")
		return "", ""
	}

	if projectName == "" {
		projectName = os.Getenv("CI_PROJECT_TITLE")
	}
	
	if projectVersion == "" {
		projectVersion = os.Getenv("CI_COMMMIT_REF_NAME")
	}

	return projectName, projectVersion
}

