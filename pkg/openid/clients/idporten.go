package clients

type idporten struct {
	*BaseConfig
}

func (in *BaseConfig) IDPorten() Configuration {
	return &idporten{
		BaseConfig: in,
	}
}
