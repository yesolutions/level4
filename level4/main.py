import argparse
import json
import os
import pathlib
import subprocess
import sys
from typing import Literal

_MANIFEST_STANDALONE_TEMPLATE = '''\
version: "1"

# the name which is used to uniquely name the cloudformation stack and will appear as in defaults for many resources
# this name must be unique per account/region
name: {name}



environments:
  - dev
  - staging
  # you can also customize certain attributes per environment, like account or region
  # this can be useful for solutions deployed to multiple regions
  # or where environments may be separated by account/region for security, regulatory, or other reasons
  - name: production
    account: 1234567890
    region: us-east-1
  - name: eu-production
    account: 0987654321
    region: eu-west-2
    # you can also configure provider overrides per-environment
    # provider_config:
    #   default_hosted_zone_name: 'my-apex-domain.eu'



# you may specify specific region(s) in which your stacks will be created
# if omitted, region is determined by your default AWS_REGION resolved from your AWS configuration
# if multiple regions are configured, a stack will be created for each combination of region and environment name,
# for each environment that does not specify its region explicitly
regions:
 - us-east-1

# You can customize the Provider class used
# provider_class: 'app.MyProvider'

# provide provider level configurations:
provider_config:
  default_hosted_zone_name: 'my-apex-domain.com'  # use this zone by default when resources need DNS names, but no explicit name is given
  vpc_lookup_params:  # help find correct VPC -- for example, if you separate environments by VPC
    vpc_name: '{{ environment_name }}-managed-vpc'


resources:
  # default configuration of resources for all environments
  default:
    buckets:
      mybucket:
        bucket_name: "{name}-mybucket-{{{{ environment_name }}}}"
        encryption: S3_MANAGED

  # override resource configurations for specific environments
  # hashes are merged with configuration specified in the `default` section
  production:
    buckets:
      mybucket:
        bucket_name: "my-override-name-for-production"
'''

_MANIFEST_APP_TEMPLATE = '''\
version: "1"

# the name which is used to uniquely name the cloudformation stack and will appear as in defaults for many resources
# this name must be unique per account/region
name: {name}


resources:
  # default configuration of resources for all environments
  default:
    buckets:
      mybucket:
        bucket_name: "{name}-mybucket-{{{{ environment_name }}}}"
        encryption: S3_MANAGED

  # override resource configurations for specific environments
  # hashes are merged with configuration specified in the `default` section
  production:
    buckets:
      mybucket:
        bucket_name: "my-override-name-for-production"
'''

_APP_TEMPLATE = '''\
#!/usr/bin/env python3
import os
from level4 import EnvironmentProvider
import aws_cdk as cdk

from {pyname}.{pyname}_stack import {camel_name}Stack


class {camel_name}Provider(EnvironmentProvider):
    ...
    # You can customize many things by implementing/overriding methods in the provider
    # TODO: add examples

production_provider = {camel_name}Provider(environment_name='production', account=os.getenv('CDK_DEFAULT_ACCOUNT'), region=os.getenv('CDK_DEFAULT_REGION'))

# for an overview of configuration options, see: <doc link>

app = cdk.App()
production_stack = {camel_name}Stack.from_manifest_file(app, '{manifest_path}', provider=production_provider)
app.synth()
'''

_APP_STACK_TEMPLATE = '''\
# from aws_cdk import (
#     Duration,
#     aws_sqs as sqs,
#     aws_s3 as s3
# )

from level4 import ManifestStack

# from level4.model import BucketResource


class {camel_name}Stack(ManifestStack):
    ...

    # You can customize many things at the stack level by implementing/overriding methods in your stack class
    # although these configurations are all possible just by editing the manifest, it can be useful to
    # have different levels at which customization is possible, as stack classes can be reused across many manifest files, for example.


    # if you wish to add resources or make other modifications in addition to those defined in the manifest file
    # uncomment the following:

    # def __init__(self, *args, **kwargs):
    #     super().__init__(self, *args, **kwargs)  # perform the creation from manifest
    #
    #     # create an additional resource, just like you would in any other CDK stack
    #     # as an example:
    #     queue = sqs.Queue(
    #         self, "my-queue",
    #         visibility_timeout=Duration.seconds(300),
    #     )

    # you can also just override specific methods to customize resource creation with manifest definitions
    # for example, to make all buckets in the defined manifest public, you can uncomment the following:

    # def create_bucket(self, id: str, bucket_definition: BucketResource) -> s3.Bucket:
    #     bucket = super().create_bucket(id, bucket_definition=bucket_definition)
    #     bucket.grant_public_access()
    #     return bucket

'''


def _init():
    subprocess.run(['cdk', 'init', 'app', '--language', 'python'], check=True, shell=True)


def _init_standalone(name) -> int:
    _init()
    pyname = name.replace('-', '_')
    manifest_path = f'{pyname}/{name}-l4-manifest.yaml'
    os.remove('app.py')
    stack_name = f'{pyname}/{pyname}_stack.py'
    os.remove(stack_name)
    os.remove(f'{pyname}/__init__.py')
    with open(manifest_path, 'w') as f:
        f.write(_MANIFEST_STANDALONE_TEMPLATE.format(name=name, pyname=pyname, manifest_path=manifest_path))
    with open('cdk.json', 'r') as f:
        cdkjson = json.load(f)

    cdkjson['app'] = f'python -m level4.app {name}/{name}-l4-manifest.yaml'
    with open('cdk.json', 'w') as f:
        json.dump(cdkjson, f, indent=4)
    return 0


def _init_app(name) -> int:
    _init()
    pyname = name.replace('-', '_')
    camel_name = ''.join(part.title() for part in pyname.split('_'))
    manifest_path = f'{pyname}/{name}-l4-manifest.yaml'
    stack_file = f'{pyname}/{pyname}_stack.py'
    with open(stack_file, 'w') as f:
        f.write(_APP_STACK_TEMPLATE.format(name=name, pyname=pyname, camel_name=camel_name, manifest_path=manifest_path))
    with open(manifest_path, 'w') as f:
        f.write(_MANIFEST_APP_TEMPLATE.format(name=name, pyname=pyname, camel_name=camel_name, manifest_path=manifest_path))
    with open('app.py', 'w') as f:
        f.write(_APP_TEMPLATE.format(name=name, pyname=pyname, camel_name=camel_name, manifest_path=manifest_path))
    return 0


def init(level4_template: Literal['standalone', 'app'], cdk_args: list[str]) -> int:
    name = pathlib.Path(os.getcwd()).name
    if level4_template == 'standalone':
        return _init_standalone(name)
    elif level4_template == 'app':
        return _init_app(name)
    else:
        print('invalid template', level4_template, file=sys.stderr)
        return 1


def main():
    parser = argparse.ArgumentParser('level4')
    subparsers = parser.add_subparsers(title='subcommands', description='valid subcommands', dest='command')
    init_parser = subparsers.add_parser('init')
    init_parser.add_argument('--level4-template', type=str, choices=('standalone', 'app'), default='app')
    init_parser.add_argument('cdk_init_args', nargs='*', action='append', help='additional arguments passed to `cdk init`')
    args = parser.parse_args()
    if args.command == 'init':
        raise SystemExit(init(level4_template=args.level4_template, cdk_args=args.cdk_init_args))
