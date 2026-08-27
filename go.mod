module acr-core

go 1.25.0

require (
	github.com/nats-io/nats.go v1.45.0
	github.com/nats-io/nats-server/v2 v2.11.8
	github.com/rivulet-io/hub v0.0.0
)

replace github.com/rivulet-io/hub => ../../05-message-bus/hub
