# Docker checks

|ID|Severity|Name|Framework
|---|---|---|---|
|DOCKER_01|DENY|Not specifying USER|   |
|DOCKER_02|DENY|Using root alias|   |
|DOCKER_03|WARN|Using latest tag|   |
|DOCKER_04|DENY|Using sudo|   |
|DOCKER_05|DENY|Using ADD|   |
|DOCKER_06|DENY|cURL/wget bashing|   |
|DOCKER_07|DENY|Using a port out of range|   |

## Make an exception

If you specify the LABEL `"embark.dev/opa-docker"="<comma separated list of ids>"` you can ignore checks for an asset.

## Links

* [Dockerfile best practices](https://docs.docker.com/develop/develop-images/dockerfile_best-practices/)
* [Cloudberry engineering best practices](https://cloudberry.engineering/article/dockerfile-security-best-practices/)
* [Hadolint rules](https://github.com/hadolint/hadolint#rules)
