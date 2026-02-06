[![Go build](https://github.com/Netcracker/qubership-core-lib-go/actions/workflows/go-build.yml/badge.svg)](https://github.com/Netcracker/qubership-core-lib-go/actions/workflows/go-build.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?metric=coverage&project=Netcracker_qubership-core-lib-go)](https://sonarcloud.io/summary/overall?id=Netcracker_qubership-core-lib-go)
[![duplicated_lines_density](https://sonarcloud.io/api/project_badges/measure?metric=duplicated_lines_density&project=Netcracker_qubership-core-lib-go)](https://sonarcloud.io/summary/overall?id=Netcracker_qubership-core-lib-go)
[![vulnerabilities](https://sonarcloud.io/api/project_badges/measure?metric=vulnerabilities&project=Netcracker_qubership-core-lib-go)](https://sonarcloud.io/summary/overall?id=Netcracker_qubership-core-lib-go)
[![bugs](https://sonarcloud.io/api/project_badges/measure?metric=bugs&project=Netcracker_qubership-core-lib-go)](https://sonarcloud.io/summary/overall?id=Netcracker_qubership-core-lib-go)
[![code_smells](https://sonarcloud.io/api/project_badges/measure?metric=code_smells&project=Netcracker_qubership-core-lib-go)](https://sonarcloud.io/summary/overall?id=Netcracker_qubership-core-lib-go)

# Core

**Go Core** library provides common functionality for Go based microservices

## Packages

|Package|Description|Documentation|
|---|---|---|
|configloader|Allows to download properties from different property sources|[Readme](configloader/README.md)|
|logging|Module for convenient logging|[Readme](logging/README.md)|
|context-propagation|Allows to propagate contexts|[Readme](context-propagation/README.md)|
|memlimit|Sets soft memory limit - 0.9 from cgroup limits at startup|[Readme](memlimit/README.md)|
|tokensource|Util for getting k8s tokens|[Readme](security/tokensource/README.md)|
|tokenverifier|Util for verifying k8s projected volume tokens|[Readme](security/tokensource/README.md)|
