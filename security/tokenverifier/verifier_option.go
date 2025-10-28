package tokenverifier

import "github.com/golang-jwt/jwt/v5"

type VerifierOptions func(*KubernetesVerifier)

type Validation func(token *jwt.Token) (bool, error)

func WithValidations(validations []Validation) VerifierOptions {
	return func(p *KubernetesVerifier) {
		p.validations = validations
	}
}
