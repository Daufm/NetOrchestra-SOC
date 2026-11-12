module netorchestra/worker

go 1.22.2

require (
	golang.org/x/crypto v0.31.0
	golang.org/x/sys v0.28.0
)

replace golang.org/x/crypto => github.com/golang/crypto v0.31.0

replace golang.org/x/sys => github.com/golang/sys v0.28.0
