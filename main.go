// importscan demonstrates the process of uploading a scan report into dependencytrack.
//
// Details of the import are defined by an ImportScan struct.
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"os"
	"encoding/base64"
	"encoding/json"

	"github.com/caarlos0/env/v11"
	dtrack "github.com/DependencyTrack/client-go" 
)

type Config struct {
    URL    string `env:"TRIVY_DEPENDENCYTRACK_URL" localhost:"8081"`
    APIKEY   string `env:"TRIVY_DEPENDENCYTRACK_APIKEY" envDefault:"xxxxxxxxx"`
    PROJECT_NAME  string `env:"TRIVY_DEPENDENCYTRACK_PROJECTNAME" envDefault:""`
    PROJECT_VERSION  string `env:"TRIVY_DEPENDENCYTRACK_PROJECTVERSION" envDefault:""`
    AUTOCREATE bool `env:"TRIVY_DEPENDENCYTRACK_PROJECTAUTOCREATE" envDefault:"false"`
    BOM_FILE  string `env:"TRIVY_DEPENDENCYTRACK_BOM_FILE" envDefault:""`
}

var cfg = Config{};

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
 
if err := env.Parse(&cfg); err != nil {
	return err
}


// Validate required variables configuration
if cfg.URL == "" {
	panic("TRIVY_DEPENDENCYTRACK_URL is required")
}
if cfg.APIKEY == "" {
	panic("TRIVY_DEPENDENCYTRACK_APIKEY is required")
}
if cfg.BOM_FILE == "" {
	panic("TRIVY_DEPENDENCYTRACK_BOM_FILE is required")
}
if cfg.PROJECT_NAME == "" {
	panic("TRIVY_DEPENDENCYTRACK_PROJECTNAME is required")
}

jcfg, _ := json.Marshal(cfg)
fmt.Println(string(jcfg))


client, _ := dtrack.NewClient(cfg.URL, dtrack.WithAPIKey(cfg.APIKEY))

bomContent, err := os.ReadFile(cfg.BOM_FILE)
if err != nil {
	panic("readfile: " + err.Error())
}

uploadToken, err := client.BOM.Upload(context.TODO(), dtrack.BOMUploadRequest{
	ProjectName:    cfg.PROJECT_NAME,
	ProjectVersion: cfg.PROJECT_VERSION,
	AutoCreate:     cfg.AUTOCREATE,
	BOM:            base64.StdEncoding.EncodeToString(bomContent),
})
if err != nil {
	panic(err)
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

