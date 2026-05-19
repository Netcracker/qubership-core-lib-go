# memlimit-go-usage

Agent-package with rules for auto-configuring `GOMEMLIMIT` in Go
microservices — aligns the Go runtime's memory ceiling with the
container's cgroup limit. The agent applies it automatically when
working with Go code in a Qubership service.
