wonderwall:
	go build -trimpath -ldflags "-s -w" -a -o bin/wonderwall ./cmd/wonderwall

local: fmt
	go run cmd/wonderwall/main.go \
	  --openid.client-id=bogus \
	  --openid.client-jwk='{"p":"7ArLiatF4ySLaU9d3M08AODbz3AsyGqEUbxEDrzMn_lX7Cbq3CPjpJ6sUj7pEu3ayFy2b1r24zlkete7pQ7mYtAVlnXrYPX-dwinC80fEAeuWo_rQ61Q4XU3vj_b7ssKZjG2uukRiJVM-rCLKc9R3CKDjig8bEwCEvg28NkrMYE","kty":"RSA","q":"mpDAdwIGL_F4FH2fJIR89YdOs8nhLYr3pXg7v50CjkAV3jfusLtNZzxvMKlDfgP8uX4YpUNbzMtAtMEPTQhUQK7HYg48MmxpHmQExjMl_7VvZ3X_TyTsfnNssYRV3MVbFIR0Cu5GbqyZgQcdk0CSIiwSeKV4ZYGRSbEXdqebZ_E","d":"eFUj03_LiH8wa_4470EHEJKrUWN04N0H1kFzangkl-T_3vl4DG0GgIcXvf9KEGF3CrIUV61kitlSuDi5CR95TpD62nSm25MJN5Fu0JiYu4oh7S3g49Qyy4nJUsLXjk6BQYRKMdszJGNGs-vUjqwjX5f6VSWnWEo8ckQsj4Tq4ptovJU4UkDt22-rL4O2AwOIohFGKRL0j4vDaeVziC0ebck-mXb4H-HFdVUA2uwegX5XJ9GPYTyNru_s75Ekm0v1qi4XQPvQgu8Y5GSxQglTJpVOuc4DIbrvclQQoO_xHEgdc34plbgdFp0icJy7OCBh-mbBys2F6V4ioYCTECNAAQ","e":"AQAB","use":"sig","kid":"jkn620gkOzlyJ4ENtdjmQeiY3ZtzGnV-qsUfOs6RuQ4","qi":"RUwY860-UAzFPLnknM5kJndezwhxdEL9m4M8fTduN9LgkHvlIP6w8_r215aqG8sl2xpym3yyOx196ElPYTG5CDxZZ2QndoBTqeZzeXtZUxGeZuDQ7sWCWusnuCvKKRHg9kJ1R6AwFH7-tslAcKX_uv7ygj3pLFBqepLBKDHSk7o","dp":"FiAA6huaxmrDgpCE7NB0AmURVYVfPT32vy6Vdogt6gTWP_V56D6Y9PJGlsL81-BhtIw0MYXmRHA5weX82cDmyXZVv6-363PDcWbnOYz1j2wY5LY-yC4zuZ5iJjwYIm73v5KDXUvBb_sGpyzrLnUXaDn3-Ng-qawKObr4c2T3zoE","alg":"RS256","dq":"XNLdoxrmGFjNopCmyEmAufteen6c6rrwasFAMJzccg1ulJvGjwCNRZh3tiOQ0tcWKVfe-TDwqpbN7z-aLsr3vji4qNyfrjCJGKU8cMM66MxPcTTd9OvZ0z8CYcF1xzYGstWw0vex-LlTHrflPQ-kMz2Agk_tdBhR5o2h57JUlCE","n":"joP1-SICCXNBFCoRA1cKVVESCvMJ0-SBLlfCUnA19g02KhY9GB396oXeDFHnbHTWtz41tcPzrTw0VvP6PCTfm2EyDcP5tZTENBXwigIwk5w1ZxKbc3Vj47VV9XiqB8zZi-MvqR_2hgHA98Iodrtt8BBnipp28QSl8BalFTa2WO8JQPkrKYvhebU1VLMogdfPF0U8LYzbp_x6niFrARlExurnzmMy5QLO5VVsjWkyE4sod2cT9xeAzyeEWRbWBT6j5OF-Hnbuwcc8ZNnQLoHuK4UdeKuH5utnAIe69RZ0PUbquKnaQHXrjmkr4Dfy7zopu58mh09ERUkZ0bME8q-BcQ"}' \
	  --openid.well-known-url=http://localhost:8888/default/.well-known/openid-configuration \
	  --ingress=http://localhost:3000 \
	  --bind-address=127.0.0.1:3000 \
	  --upstream-host=localhost:4000 \
	  --redis.uri=redis://localhost:6379 \
	  --log-level=debug \
	  --log-format=text

test: fmt
	go test -count=1 -shuffle=on ./... -coverprofile cover.out

check:
	go vet ./...
	go run honnef.co/go/tools/cmd/staticcheck ./...
	go run golang.org/x/vuln/cmd/govulncheck -show=traces ./...

fmt:
	go run mvdan.cc/gofumpt -w ./
