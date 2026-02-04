package cmd

import (
	"context"
	"fmt"
	"time"

	"encoding/base64"
	"os"

	"github.com/weeros/trivy-plugin-dependencytrack/cmd/common"
	"github.com/weeros/trivy-plugin-dependencytrack/pkg/logger"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	dtrack "github.com/DependencyTrack/client-go"
)

func NewUploadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "upload [flags]",
		Short:         "Upload a DependencyTrack package",
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			urlApi := viper.GetString(common.VUrlApi)
			apikey := viper.GetString(common.VApiKey)
			ProjectName := viper.GetString(common.VProjectName)
			ProjectVersion := viper.GetString(common.VProjectVersion)
			AutoCreate := viper.GetBool(common.VAutoCreate)
			BomFile := viper.GetString(common.VBomFile)
			gitlabBranch := viper.GetBool(common.VGitlabBranch)
			gitlabTag := viper.GetBool(common.VGitlabTag)
			gitlabMR := viper.GetBool(common.VGitlabMR)
			err := upload(urlApi, apikey, ProjectName, ProjectVersion, AutoCreate, BomFile, gitlabBranch, gitlabTag, gitlabMR, false)
			if err != nil {
				logger.Default().Error("Error uploading DependencyTrack sbom", "error", err)
				return err
			}
			return nil
		},
		Example: `
# Upload a local dependencytrack sbom:
trivy dependencytrack upload --url-api http://dependencytrack.local:8081 --apikey <API_KEY> --project-name my-project --project-version 1.0.0 --bom-file ./sbom.json



export TRIVY_PLUGIN_DEPENDENCYTRACK_URL=http://localhost:8081
export TRIVY_PLUGIN_DEPENDENCYTRACK_APIKEY=<API_KEY>
export TRIVY_PLUGIN_DEPENDENCYTRACK_BOM_FILE=result.json
export TRIVY_PLUGIN_DEPENDENCYTRACK_AUTOCREATE=true
export TRIVY_PLUGIN_DEPENDENCYTRACK_PROJECT_NAME=my-project
export TRIVY_PLUGIN_DEPENDENCYTRACK_PROJECT_VERSION=1.0.0
trivy dependencytrack upload 
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



func upload(url string, apikey string, projectName string, projectVersion string, autoCreate bool, bomFile string, gitlabBranch bool, gitlabTag bool, gitlabMR bool, gitlabMode bool) error {
 
	if url == "" {
		err := fmt.Errorf("dependencytrack url-api is required")
		logger.Default().Error("Error validating dependencytrack url-api", "error", err)
		return err
	}
	
	if apikey == "" {
		err := fmt.Errorf("dependencytrack apikey is required")
		logger.Default().Error("Error validating dependencytrack apikey", "error", err)
		return err
	}
	
	client, _ := dtrack.NewClient(url, dtrack.WithAPIKey(apikey))

	bomContent, err := os.ReadFile(bomFile)
	if err != nil {
		logger.Default().Error("Error reading dependencytrack bom file", "error", err.Error())
		return err
	}


	if gitlabMode == true {
		projectName, projectVersion = gitlabGenerateProjectInfo(projectName, projectVersion, gitlabBranch, gitlabTag, gitlabMR)
	}
	

	if projectName == "" {
		err := fmt.Errorf("dependencytrack project-name is required")
		logger.Default().Error("Error missing dependencytrack project-name", "error", err)
		return err
	}


	if projectVersion == "" {
		err := fmt.Errorf("dependencytrack project-version is required")
		logger.Default().Error("Error missing dependencytrack project-version", "error", err)
		return err
	}
	
	if bomFile == "" {
		err := fmt.Errorf("dependencytrack bom-file is required")
		logger.Default().Error("Error missing dependencytrack bom-file", "error", err)
		return err
	}

	uploadToken, err := client.BOM.Upload(context.TODO(), dtrack.BOMUploadRequest{
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		AutoCreate:     autoCreate,
		BOM:            base64.StdEncoding.EncodeToString(bomContent),
	})
	if err != nil {
		logger.Default().Error("Error uploading dependencytrack bom file", "error", err.Error())
		return err
	}

	var (
		doneChan = make(chan struct{})
		errChan  = make(chan error)
		ticker   = time.NewTicker(1 * time.Second)
		timeout  = time.After(30 * time.Second)
	)
	
	go func() {
		defer func() {
			close(doneChan)
			close(errChan)
		}()

		for {
			select {
			case <-ticker.C:
				processing, err := client.Event.IsBeingProcessed(context.TODO(), dtrack.EventToken(uploadToken))
				if err != nil {
					errChan <- err
					return
				}
				if !processing {
					
					doneChan <- struct{}{}
					return
				}
			case <-timeout:
				errChan <- fmt.Errorf("timeout exceeded")
				return
			}
		}
	}()

		

	select {
	case <-doneChan:
		fmt.Println("bom processing completed")
	case err = <-errChan:
		fmt.Printf("failed to wait for bom processing: %v\n", err)
	}

	return nil
}
