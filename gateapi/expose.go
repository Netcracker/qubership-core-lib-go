package gateapi

import automem "github.com/KimMachineGun/automemlimit/memlimit"

func Capped(limit uint64) automem.Provider {
	return automem.Limit(limit)
}
