package clients

type idporten struct {
	*OpenIDConfig
}

func (in *OpenIDConfig) IDPorten() Configuration {
	return &idporten{
		OpenIDConfig: in,
	}
}
