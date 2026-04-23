package rest

import (
	"fmt"
)

const (
	kubernetesTokenAcquisitionError = "error acquiring kubernetes token for m2m communication.\n" +
		"the current version of the security library expects a kubernetes token with the required audience to be mounted in the deployment.\n" +
		"if you do not intend to use a kubernetes token at this time, please roll back to a previous version of the library.\n" +
		"otherwise, make sure that a kubernetes token with the required audience is properly mounted.\n" +
		"the previous authentication method will be used as a fallback."
	kubernetesTokenUnauthorizedError = "unauthorized access (http 401).\n" +
		"during an m2m interaction attempt using a kubernetes token with the required audience, a 401 error was received.\n" +
		"the possible cause is an outdated version of the security library on the server side.\n" +
		"the previous authentication method will be used as a fallback."
)

type fallbackReason struct {
	desc string
	url  string
	err  error
}

func (f *fallbackReason) Message() string {
	if f.err != nil {
		return fmt.Sprintf("failed to establish m2m connection to %s\n%s\n%v", f.url, f.desc, f.err.Error())
	}
	return fmt.Sprintf("failed to establish m2m connection to %s\n%s", f.url, f.desc)

}

type TokenAcquisitionError struct {
	Err error
}

func (e *TokenAcquisitionError) Error() string {
	return fmt.Sprintf("failed to acquire m2m token: %v", e.Err)
}
