package config

import (
	flag "github.com/spf13/pflag"
)

const (
	RedisAddress  = "redis.address"
	RedisPassword = "redis.password"
	RedisTLS      = "redis.tls"
	RedisUsername = "redis.username"
)

type Redis struct {
	Address  string `json:"address"`
	Username string `json:"username"`
	Password string `json:"password"`
	TLS      bool   `json:"tls"`
}

func redisFlags() {
	flag.String(RedisAddress, "", "Address of Redis. An empty value will use in-memory session storage.")
	flag.String(RedisPassword, "", "Password for Redis.")
	flag.Bool(RedisTLS, true, "Whether or not to use TLS for connecting to Redis.")
	flag.String(RedisUsername, "", "Username for Redis.")
}
