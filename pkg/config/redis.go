package config

import (
	"crypto/tls"

	"github.com/redis/go-redis/v9"
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

func (r *Redis) Client() (*redis.Client, error) {
	opts := &redis.Options{
		Network:      "tcp",
		Addr:         r.Address,
		Username:     r.Username,
		Password:     r.Password,
		MinIdleConns: 1,
	}

	if r.TLS {
		opts.TLSConfig = &tls.Config{}
	}

	redisClient := redis.NewClient(opts)
	return redisClient, nil
}

func redisFlags() {
	flag.String(RedisAddress, "", "Address of Redis. An empty value will use in-memory session storage.")
	flag.String(RedisPassword, "", "Password for Redis.")
	flag.Bool(RedisTLS, true, "Whether or not to use TLS for connecting to Redis.")
	flag.String(RedisUsername, "", "Username for Redis.")
}
