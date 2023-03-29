package config

import (
	"crypto/tls"
	"time"

	"github.com/redis/go-redis/v9"
	flag "github.com/spf13/pflag"
)

const (
	RedisAddress               = "redis.address"
	RedisPassword              = "redis.password"
	RedisTLS                   = "redis.tls"
	RedisUsername              = "redis.username"
	RedisConnectionIdleTimeout = "redis.connection-idle-timeout"
)

type Redis struct {
	Address               string `json:"address"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	TLS                   bool   `json:"tls"`
	ConnectionIdleTimeout int    `json:"connection-idle-timeout"`
}

func (r *Redis) Client() (*redis.Client, error) {
	opts := &redis.Options{
		Network:      "tcp",
		Addr:         r.Address,
		Username:     r.Username,
		Password:     r.Password,
		MinIdleConns: 1,
		MaxRetries:   5,
	}

	if r.TLS {
		opts.TLSConfig = &tls.Config{}
	}

	if r.ConnectionIdleTimeout > 0 {
		opts.ConnMaxIdleTime = time.Duration(r.ConnectionIdleTimeout) * time.Second
	} else if r.ConnectionIdleTimeout == -1 {
		opts.ConnMaxIdleTime = -1
	}

	redisClient := redis.NewClient(opts)
	return redisClient, nil
}

func redisFlags() {
	flag.String(RedisAddress, "", "Address of Redis. An empty value will use in-memory session storage.")
	flag.String(RedisPassword, "", "Password for Redis.")
	flag.Bool(RedisTLS, true, "Whether or not to use TLS for connecting to Redis.")
	flag.String(RedisUsername, "", "Username for Redis.")
	flag.Int(RedisConnectionIdleTimeout, 0, "Idle timeout for Redis connections, in seconds. If non-zero, the value should be less than the client timeout configured at the Redis server. A value of -1 disables timeout. Default is 30 minutes.")
}
