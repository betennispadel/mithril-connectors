module github.com/betennispadel/mithril-connectors/secrets/gitleaks

go 1.26.0

require github.com/betennispadel/mithril-connectors/sdk v0.0.0

require (
	google.golang.org/grpc v1.85.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

replace github.com/betennispadel/mithril-connectors/sdk => ../../sdk
