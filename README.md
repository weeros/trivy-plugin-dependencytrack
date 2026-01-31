# trivy-plugin-template
Template for Trivy plugins

**NOTE: Replace <org_name>, trivy-plugin-dependencytrack and <plugin_name> in go.mod, goreleaser.yaml and plugin.yaml with the appropriate values.**

## Installation
```shell
trivy plugin install github.com/weeros/trivy-plugin-dependencytrack
```

## Usage

```shell
trivy dependencytrack
```


## Devlopments

```bash
go get -u
```

```bash
GOPROXY=https://proxy.golang.org go mod tidy
````


```bash
mkdir -p ~/.trivy/plugins/dependencytrack
cp plugin.yaml ~/.trivy/plugins/defectdojo
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o ~/.trivy/plugins/dependencytrack/dependencytrack  main.go 
```
