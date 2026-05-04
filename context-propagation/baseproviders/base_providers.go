package baseproviders

import (
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/acceptlanguage"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/allowedheaders"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/apiversion"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/businessprocess"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/clientip"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/originatingbiid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/tenant"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xchannelrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xrequestid"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversion"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/baseproviders/xversionname"
	"github.com/netcracker/qubership-core-lib-go/v3/context-propagation/ctxmanager"
)

func Get() []ctxmanager.ContextProvider {
	return []ctxmanager.ContextProvider{
		acceptlanguage.AcceptLanguageProvider{},
		xversion.XVersionProvider{},
		xversionname.XVersionNameProvider{},
		apiversion.ApiVersionProvider{},
		xrequestid.XRequestIdProvider{},
		allowedheaders.NewAllowedHeaderProvider(),
		businessprocess.BusinessProcessProvider{},
		originatingbiid.OriginatingBiIdProvider{},
		clientip.ClientIpProvider{},
		tenant.TenantProvider{},
		xchannelrequestid.XChannelRequestIdProvider{},
	}
}
