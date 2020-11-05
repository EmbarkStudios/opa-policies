# OPA Policies
The Open Policy Agent (OPA, pronounced “oh-pa”) is an open source, general-purpose policy engine that unifies policy enforcement across the stack. OPA provides a high-level declarative language that let’s you specify policy as code and simple APIs to offload policy decision-making from your software. You can use OPA to enforce policies in microservices, Kubernetes, CI/CD pipelines, API gateways, and more.

The policies are written in a language called [rego](https://www.openpolicyagent.org/docs/latest/policy-language/). You can find examples of policies for different technologies [here](https://github.com/open-policy-agent/conftest/tree/master/examples).

## Structure
Each type will have its own folder (and namespace) inside of [policy](policy). If you want to add a new type, you can refer to [policy/docker](policy/docker).

## How to use it
[conftest](https://www.conftest.dev/) is a utility to help you write tests against structured configuration data. For instance, you could write tests for your Kubernetes configurations, Tekton pipeline definitions, Terraform code, Serverless configs or any other structured data.

You can find information on how to install conftest [here](https://www.conftest.dev/install/)

## Writing tests
We can unit-test our policies. You can find more information on how to write tests [here](https://www.openpolicyagent.org/docs/latest/policy-testing/) and see the [tests for our Dockerfile policies](policy/docker/security_test.rego).

You can run the tests by executing `conftest verify`

## Excluding policies
You can find more information on how to except policies [here](https://www.conftest.dev/exceptions/).


## Example usage
Given the following Dockerfile:
```
FROM ubuntu:latest # will warn due to "latest"

WORKDIR /app

# will fail due to "root"
USER root

# will fail due to usage of ADD instead of COPY
ADD app /app 

COPY README.md /app/README.md
RUN sudo apt-get udpate # will fail due to "sudo"

# will fail due to curl/wget bashing
RUN wget https://some-url.com | sh

RUN apt-get update && apt-get install -y htop

CMD ["/bin/bash", "/app/entrypoint.sh"]
```
Running `conftest test ../Dockerfile --namespace docker` will produce the following output given the current rules in [policy/docker](policy/docker):
```
WARN - Dockerfile - Do not use latest tag with image: ["ubuntu:latest"]
FAIL - Dockerfile - Avoid using 'sudo' command: sudo apt-get udpate
FAIL - Dockerfile - Use COPY instead of ADD: app /app
FAIL - Dockerfile - Use COPY instead of ADD: code /tmp/code
FAIL - Dockerfile - Avoid curl/wget bashing
```
