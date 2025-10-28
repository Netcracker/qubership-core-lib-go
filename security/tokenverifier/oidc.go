package tokenverifier

type OidcResponse struct {
	JwksUri string `json:"jwks_uri"`
	Issuer  string `json:"issuer"`
}
