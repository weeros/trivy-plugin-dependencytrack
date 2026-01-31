module github.com/weeros/dependencytrack

go 1.24

toolchain go1.24.1

require github.com/caarlos0/env/v11 v11.3.1

require (
	github.com/DependencyTrack/client-go v0.18.0 // indirect
	github.com/google/uuid v1.3.0 // indirect
	golang.org/x/mod v0.20.0 // indirect
)

//replace github.com/truemilk/go-dependencytrack v0.6.3 => ../go-dependencytrack
