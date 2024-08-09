#!/usr/bin/env sh
set -x

CMD_PKG='github.com/topicuskeyhub/aws-keyhub/cmd'
GO_VERSION=$(go version | cut -c 14- | cut -d' ' -f1)
GIT_TAG=$(git describe --tags | cut -d- -f1)
GIT_HASH=$(git rev-parse --short HEAD)

LDFLAG="-X $CMD_PKG.GitHash=$GIT_HASH"
LDFLAG="$LDFLAG -X $CMD_PKG.GoVersion=$GO_VERSION"
LDFLAG="$LDFLAG -X $CMD_PKG.GitTag=$GIT_TAG"

GOOS=linux GOARCH=amd64 go build -ldflags "$LDFLAG" -o build/linux-amd64/aws-keyhub 
GOOS=windows GOARCH=amd64 go build -ldflags "$LDFLAG" -o build/windows-amd64/aws-keyhub.exe
GOOS=darwin GOARCH=amd64 go build -ldflags "$LDFLAG" -o build/darwin-amd64/aws-keyhub 
GOOS=darwin GOARCH=arm64 go build -ldflags "$LDFLAG" -o build/darwin-arm64/aws-keyhub 

# Make release zips
mkdir -p release/
zip -j release/aws-keyhub-linux-amd64.zip build/linux-amd64/*
zip -j release/aws-keyhub-windows-amd64.zip build/windows-amd64/*
zip -j release/aws-keyhub-darwin-arm64.zip build/darwin-arm64/*
zip -j release/aws-keyhub-darwin-amd64.zip build/darwin-amd64/*
