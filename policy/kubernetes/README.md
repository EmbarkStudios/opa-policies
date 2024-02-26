# Kubernetes checks

|ID|Severity|Name|Framework
|---|---|---|---|
|K8S_01|DENY|Allowing privilege escalation|   |
|K8S_02|DENY|Force run as non root|   |
|K8S_03|DENY|Using latest tag|   |
|K8S_04|DENY|Using default namespace|   |
|K8S_05|DENY|Adding SYS_ADMIN capabilities|   |
|K8S_06|DENY|Using default service account|   |
|K8S_07|DENY|Using deprecated service account|   |
|K8S_09|WARN|Missing CPU requests|
|K8S_10|DENY|Allowing mounting Docker socket volume|
|K8S_11|WARN|Specifying hostPort|
|K8S_12|WARN|Missing Memory limits|
|K8S_13|WARN|Missing Memory requests| |
|K8S_14|DENY|Non read only root file-system|
|K8S_15|DENY|Managing hostAlias|
|K8S_16|DENY|Sharing Host IPC namespace|
|K8S_17|DENY|Sharing Host PID namespace|
|K8S_18|DENY|Sharing Host Network namespace|
|K8S_19|DENY|Running as user id that is too low|
|K8S_20|WARN|Missing liveness probes|
|K8S_21|WARN|Missing readiness probes|

## Make an exception

If you specify the annotation `embark.dev/opa-k8s: <comma separated list of ids>` you can ignore checks for an asset.

## Links

* [Checkov](https://github.com/bridgecrewio/checkov/checkov/kubernetes/checks)
* [Gareth/security.rego](https://gist.githubusercontent.com/garethr/ea41afb1b6562cdb2b1555719f51f90e/raw/02e7d15c603688d5fb7e8d3546d2a228b42222f5/security.rego)
* [kubesec.io](https://kubesec.io/basics/)
