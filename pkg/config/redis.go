package config

import (
	"crypto/tls"
	"time"

	"github.com/redis/go-redis/v9"
	flag "github.com/spf13/pflag"
)

type Redis struct {
	Address               string `json:"address"`
	Username              string `json:"username"`
	Password              string `json:"password"`
	TLS                   bool   `json:"tls"`
	URI                   string `json:"uri"`
	ConnectionIdleTimeout int    `json:"connection-idle-timeout"`
}

func (r *Redis) Client() (*redis.Client, error) {
	opts := &redis.Options{
		Network: "tcp",
		Addr:    r.Address,
	}

	if r.TLS {
		opts.TLSConfig = &tls.Config{}
	}

	if r.URI != "" {
		var err error

		opts, err = redis.ParseURL(r.URI)
		if err != nil {
			return nil, err
		}
	}

	opts.MinIdleConns = 1
	opts.MaxRetries = 5

	if r.Username != "" {
		opts.Username = r.Username
	}

	if r.Password != "" {
		opts.Password = r.Password
	}

	if r.ConnectionIdleTimeout > 0 {
		opts.ConnMaxIdleTime = time.Duration(r.ConnectionIdleTimeout) * time.Second
	} else if r.ConnectionIdleTimeout == -1 {
		opts.ConnMaxIdleTime = -1
	}

	return redis.NewClient(opts), nil
}

const (
	RedisAddress               = "redis.address"
	RedisPassword              = "redis.password"
	RedisTLS                   = "redis.tls"
	RedisUsername              = "redis.username"
	RedisURI                   = "redis.uri"
	RedisConnectionIdleTimeout = "redis.connection-idle-timeout"
)

func redisFlags() {
	flag.String(RedisURI, "", "Redis URI string. An empty value will fall back to 'redis-address'.")
	flag.String(RedisAddress, "", "Deprecated: prefer using 'redis.uri'. Address of the Redis instance (host:port). An empty value will use in-memory session storage. Does not override address set by 'redis.uri'.")
	flag.String(RedisPassword, "", "Password for Redis. Overrides password set by 'redis.uri'.")
	flag.Bool(RedisTLS, true, "Whether or not to use TLS for connecting to Redis. Does not override TLS config set by 'redis.uri'.")
	flag.String(RedisUsername, "", "Username for Redis. Overrides username set by 'redis.uri'.")
	flag.Int(RedisConnectionIdleTimeout, 0, "Idle timeout for Redis connections, in seconds. If non-zero, the value should be less than the client timeout configured at the Redis server. A value of -1 disables timeout. If zero, the default value from go-redis is used (30 minutes). Overrides options set by 'redis.uri'.")
}
