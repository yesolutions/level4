# Environment providers

An "environment" describes where solutions live.
An environment _provider_ It also controls many of the default behaviors for how CDK constructs are created, for example
default VPCs, subnets, clusters, etc.


Environment providers must define at least:
- A name for the environment, for example "production" or "staging"
- An account
- A region

## Writing a custom provider

...
