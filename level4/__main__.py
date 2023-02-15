import argparse

import aws_cdk as cdk

from level4 import ManifestLoader
from level4 import ManifestStack


def main():
    parser = argparse.ArgumentParser('level4')
    parser.add_argument('spec')
    args = parser.parse_args()

    app = cdk.App()
    loader = ManifestLoader()
    initial_manifest = loader.load(args.spec, environment_name='', account='', region='')
    environments = initial_manifest.environments
    regions = initial_manifest.regions
    for env in environments:
        if isinstance(env, str) or env.regions is None:
            for region in regions:
                if isinstance(env, str):
                    manifest = loader.load(args.spec, environment_name=env, account=initial_manifest.account, region=region)
                    provider_kwargs = {}
                    extra_kwargs = manifest.provider_config
                    provider_kwargs.update(extra_kwargs)
                    provider_kwargs.update(environment_name=env, account=manifest.account, region=region)
                else:
                    manifest = loader.load(args.spec, environment_name=env.name, account=env.account or initial_manifest.account, region=region)
                    provider_kwargs = {}
                    extra_kwargs = manifest.provider_config
                    provider_kwargs.update(extra_kwargs)
                    provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account, region=region)
                    if env.provider_config:
                        provider_kwargs.update(env.provider_config)
                ManifestStack.with_dynamic_provider(app, args.spec, provider_kwargs=provider_kwargs)
        else:
            for region in env.regions:
                manifest = loader.load(args.spec, environment_name=env.name, account=env.account or initial_manifest.account, region=region)
                provider_kwargs = {}
                extra_kwargs = manifest.provider_config
                provider_kwargs.update(extra_kwargs)
                provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account, region=region)
                if env.provider_config:
                    provider_kwargs.update(env.provider_config)
                ManifestStack.with_dynamic_provider(app, args.spec, provider_kwargs=provider_kwargs)

    app.synth()


main()
