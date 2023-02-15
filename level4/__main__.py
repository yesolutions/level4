import argparse
import aws_cdk as cdk
from level4 import ManifestStack, EnvironmentProvider, ManifestLoader
import sys

def main():
    parser = argparse.ArgumentParser('level4')
    parser.add_argument('spec')
    args = parser.parse_args()

    app = cdk.App()
    loader = ManifestLoader()
    manifest = loader.load(args.spec, environment_name='', account='', region='')
    environments = manifest.environments
    regions = manifest.regions
    extra_kwargs = manifest.provider_config
    for env in environments:
        if isinstance(env, str) or env.regions is None:
            for region in regions:
                provider_kwargs = {}
                provider_kwargs.update(extra_kwargs)
                if isinstance(env, str):
                    provider_kwargs.update(environment_name=env, account=manifest.account, region=region)
                else:
                    provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account, region=region)
                    if env.provider_config:
                        provider_kwargs.update(env.provider_config)
                ManifestStack.with_dynamic_provider(app, args.spec, provider_kwargs=provider_kwargs)
        else:
            for region in env.regions:
                provider_kwargs = {}
                provider_kwargs.update(extra_kwargs)
                provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account, region=region)
                if env.provider_config:
                    provider_kwargs.update(env.provider_config)
                ManifestStack.with_dynamic_provider(app, args.spec, provider_kwargs=provider_kwargs)

    app.synth()

main()