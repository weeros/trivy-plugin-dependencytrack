module github.com/weeros/dependencytrack

go 1.24.0

toolchain go1.24.1

require github.com/DependencyTrack/client-go v0.18.0

require (
	github.com/google/uuid v1.6.0 // indirect
	golang.org/x/mod v0.32.0 // indirect
	golang.org/x/sync v0.19.0 // indirect
)

//replace github.com/truemilk/go-dependencytrack v0.6.3 => ../go-dependencytrack
