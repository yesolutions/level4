import argparse

import aws_cdk as cdk

from level4 import ManifestLoader
from level4 import ManifestStack

def create_app(spec_files: list[str], synth=True) -> cdk.App:
    app = cdk.App()
    for spec in spec_files:
        loader = ManifestLoader()
        initial_manifest = loader.load(spec, environment_name='', account='', region='')
        environments = initial_manifest.environments
        regions = initial_manifest.regions
        for env in environments:
            if isinstance(env, str) or env.regions is None:
                for region in regions:
                    if isinstance(env, str):
                        manifest = loader.load(spec, environment_name=env, account=initial_manifest.account,
                                               region=region)
                        provider_kwargs = {}
                        extra_kwargs = manifest.provider_config
                        provider_kwargs.update(extra_kwargs)
                        provider_kwargs.update(environment_name=env, account=manifest.account, region=region)
                    else:
                        manifest = loader.load(spec, environment_name=env.name,
                                               account=env.account or initial_manifest.account, region=region)
                        provider_kwargs = {}
                        extra_kwargs = manifest.provider_config
                        provider_kwargs.update(extra_kwargs)
                        provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account,
                                               region=region)
                        if env.provider_config:
                            provider_kwargs.update(env.provider_config)
                    ManifestStack.with_dynamic_provider(app, spec, provider_kwargs=provider_kwargs)
            else:
                for region in env.regions:
                    manifest = loader.load(spec, environment_name=env.name,
                                           account=env.account or initial_manifest.account, region=region)
                    provider_kwargs = {}
                    extra_kwargs = manifest.provider_config
                    provider_kwargs.update(extra_kwargs)
                    provider_kwargs.update(environment_name=env.name, account=env.account or manifest.account,
                                           region=region)
                    if env.provider_config:
                        provider_kwargs.update(env.provider_config)
                    ManifestStack.with_dynamic_provider(app, spec, provider_kwargs=provider_kwargs)
    if synth:
        app.synth()
    return app

def main():
    parser = argparse.ArgumentParser('level4.app')
    parser.add_argument('specs', nargs='+', action='append', type=str)
    args = parser.parse_args()
    create_app(args.specs, synth=True)

