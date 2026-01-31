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
		Use:           "upload [flags] packageRef",
		Short:         "Upload a DependencyTrack package",
		SilenceUsage:  false,
		SilenceErrors: false,
		RunE: func(cmd *cobra.Command, args []string) error {
			url := viper.GetString(common.VUrl)
			token := viper.GetString(common.VApiKey)
			ProjectName := viper.GetString(common.VProjectName)
			ProjectVersion := viper.GetString(common.VProjectVersion)
			AutoCreate := viper.GetBool(common.VAutoCreate)
			BomFile := viper.GetString(common.VBomFile)
			err := upload(url, token, ProjectName, ProjectVersion, AutoCreate, BomFile)
			if err != nil {
				logger.Default().Error("Error uploadning DependencyTrack package", "error", err)
				return err
			}
			return nil
		},
		Example: `
# Upload a local dependencytrack package:
trivy dependencytrack upload dependencytrack-package-foo-amd64-1.2.3.tar.zst

# Upload a package directly from an OCI registry:
trivy dependencytrack upload oci://registry.example.com/path/to/foo:1.2.3

# Use a mirrored vulnerability database:
trivy dependencytrack upload --db-repository=https://registry.example.com/trivy-db oci://registry.example.com/path/to/foo:1.2.3`,
	}

	cmd.Flags().String(common.VUrl, common.VUrlDefault, common.VUrlUsage)
	err := viper.BindPFlag(common.VUrl, cmd.Flags().Lookup(common.VUrlLong))
	if err != nil {
		logger.Default().Error("Error binding flag to viper", "error", err)
		os.Exit(1)
	}

	cmd.Flags().String(common.VApiKey, common.VApiKeyDefault, common.VApiKeyUsage)
	err = viper.BindPFlag(common.VApiKey, cmd.Flags().Lookup(common.VApiKeyLong))
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



func upload(url string, token string, projectName string, projectVersion string, autoCreate bool, bomFile string) error {
 
	client, _ := dtrack.NewClient(url, dtrack.WithAPIKey(token))

	bomContent, err := os.ReadFile(bomFile)
	if err != nil {
		panic("readfile: " + err.Error())
	}

	uploadToken, err := client.BOM.Upload(context.TODO(), dtrack.BOMUploadRequest{
		ProjectName:    projectName,
		ProjectVersion: projectVersion,
		AutoCreate:     autoCreate,
		BOM:            base64.StdEncoding.EncodeToString(bomContent),
	})
	if err != nil {
		panic("Upload: " + err.Error())
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

