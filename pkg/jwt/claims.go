package jwt

const (
	JtiClaim = "jti"
	SidClaim = "sid"
	UtiClaim = "uti"
)

type Claims struct {
	IDTokenJti     string `json:"id_token_jti,omitempty"`
	IDTokenUti     string `json:"id_token_uti,omitempty"`
	AccessTokenJti string `json:"access_token_jti,omitempty"`
	AccessTokenUti string `json:"access_token_uti,omitempty"`
}
