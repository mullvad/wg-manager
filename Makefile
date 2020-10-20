.PHONY: fmt test vet install package
all: test vet install

fmt:
	go fmt ./...

test:
	go test -short ./...

vet:
	go vet ./...

install:
	go install ./...

package:
	sudo docker run --rm -v $(PWD):/repo -v $(PWD)/build:/build quay.io/mullvad/go-packager@sha256:7cd9d52c13f70b0b95e312609e3321bbc61e3e2f3478f5e30f7df194289a9ebb
