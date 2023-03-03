from __future__ import annotations

import abc
import enum
import functools
import importlib
import logging
import sys
import warnings
from functools import singledispatchmethod
from typing import Any
from typing import Optional
from typing import Type
from typing import Union

import aws_cdk
import constructs
import jinja2
import jsii
import pydantic
import yaml
from aws_cdk import aws_certificatemanager as certmanager
from aws_cdk import aws_cloudfront as cloudfront
from aws_cdk import aws_cloudfront_origins as cloudfront_origins
from aws_cdk import aws_ec2 as ec2
from aws_cdk import aws_ecr as ecr
from aws_cdk import aws_ecs as ecs
from aws_cdk import aws_ecs_patterns as ecs_patterns
from aws_cdk import aws_elasticache as elasticache
from aws_cdk import aws_elasticloadbalancingv2 as elbv2
from aws_cdk import aws_iam as iam
from aws_cdk import aws_logs
from aws_cdk import aws_rds as rds
from aws_cdk import aws_route53 as route53
from aws_cdk import aws_route53_targets as route53_targets
from aws_cdk import aws_s3 as s3
from aws_cdk import aws_secretsmanager as secretsmanager
from aws_cdk import aws_sns as sns
from aws_cdk import aws_sqs as sqs

# from aws_cdk import aws_kms as kms
# from aws_cdk import aws_sns_subscriptions as sns_subscriptions


class CreationDeferredException(Exception):
    """Raise this to defer creation to later"""

    ...


class ManifestVersion(enum.Enum):
    VER_1 = '1'


class Grantee(pydantic.BaseModel):
    resource_id: str


def extract_apex_from_url(url: str) -> str:
    raise NotImplementedError()


class EnvironmentProvider:
    def __init__(
        self,
        environment_name: str,
        region: str,
        account: str,
        default_hosted_zone_name: Optional[str] = None,
        vpc_lookup_params: Optional[dict[str, Any]] = None,
    ):
        self._account = account
        self._region = region
        self._environment_name: str = environment_name
        self._stack_cluster = None
        self._hosted_zone_cache = {}
        self._default_vpc = None
        self._default_hosted_zone_name = default_hosted_zone_name
        if vpc_lookup_params is None:
            self._vpc_lookup_params = {'is_default': True}
        else:
            self._vpc_lookup_params = vpc_lookup_params

    def get_vpc_default(self, scope: ManifestStack) -> ec2.IVpc:
        if self._default_vpc is not None:
            return self._default_vpc
        else:
            self._default_vpc = ec2.Vpc.from_lookup(scope, 'defaultvpc', **self._vpc_lookup_params)
            return self._default_vpc

    def get_hosted_zone_info_from_domain(self, scope: ManifestStack, domain: str) -> route53.IHostedZone:
        parts = domain.split('.')
        assert len(parts) >= 2, 'bad domain name'
        domain = '.'.join(parts[-2:])
        if domain in self._hosted_zone_cache:
            return self._hosted_zone_cache[domain]
        else:
            hosted_zone = route53.HostedZone.from_lookup(scope, f'{domain}-hosted-zone', domain_name=domain)
            self._hosted_zone_cache[domain] = hosted_zone
            return hosted_zone

    def get_default_database_instance_type(self) -> ec2.InstanceType:
        return ec2.InstanceType.of(instance_class=ec2.InstanceClass.T3, instance_size=ec2.InstanceSize.SMALL)

    def get_default_service_log_retention_period(self):
        return aws_logs.RetentionDays.ONE_YEAR

    @abc.abstractmethod
    def get_wildcard_cert_for_domain(self, scope: ManifestStack, domain: str) -> certmanager.ICertificate:
        ...

    @property
    def environment_name(self) -> str:
        return self._environment_name

    @property
    def region(self) -> str:
        return self._region

    @property
    def account(self) -> str:
        return self._account

    def default_vpc_private_subnets(self, scope: ManifestStack) -> list[str]:
        subnet_ids = self.get_vpc_default(scope).select_subnets(subnet_type=ec2.SubnetType.PRIVATE_WITH_NAT).subnet_ids
        return subnet_ids

    def get_vpc_default_public_subnets(self, scope: ManifestStack) -> list[str]:
        subnet_ids = self.get_vpc_default(scope).select_subnets(subnet_type=ec2.SubnetType.PUBLIC).subnet_ids
        return subnet_ids

    def get_vpc_default_subnets(self, scope: ManifestStack) -> list[str]:
        return self.default_vpc_private_subnets(scope) + self.get_vpc_default_public_subnets(scope)

    def get_ecs_cluster_default(self, is_fargate: bool) -> Optional[ecs.ICluster]:
        return None

    @property
    def default_service_log_retention_period(self) -> aws_logs.RetentionDays:
        return aws_logs.RetentionDays.ONE_YEAR

    def get_default_database_instance_size(self) -> str | ec2.InstanceType:
        return ec2.InstanceType.of(instance_class=ec2.InstanceClass.T3, instance_size=ec2.InstanceSize.SMALL)

    def get_default_elasticache_instance_type(self) -> str:
        return 'cache.t3.small'

    @property
    def default_tags(self) -> dict[str, str]:
        return {}

    def get_default_hosted_zone_name(self) -> str:
        if self._default_hosted_zone_name is not None:
            return self._default_hosted_zone_name
        else:
            raise NotImplementedError('Resource requested default hosted zone name, but no name is configured')


class PortRangeConfiguration(pydantic.BaseModel):
    start_port: int
    end_port: int


class ICMPTypeCodeConfiguration(pydantic.BaseModel):
    type: int | float
    code: int | float


class PortConfiguration(pydantic.BaseModel):
    tcp: Optional[int] = None
    udp: Optional[int] = None
    tcp_range: Optional[PortRangeConfiguration] = None
    udp_range: Optional[PortRangeConfiguration] = None
    icmp_type: Optional[int] = None
    icmp_type_and_code: Optional[ICMPTypeCodeConfiguration] = None
    icmp_ping: bool = False
    all_traffic: bool = False
    all_tcp: bool = False
    all_icmp: bool = False
    esp: bool = False
    ah: bool = False


class PortConnectionConfiguration(pydantic.BaseModel):
    resource_id: str
    port: PortConfiguration
    description: Optional[str] = None


class PeerConnectionConfiguration(pydantic.BaseModel):
    resource_id: str
    description: Optional[str] = None


class AnyConnectionConfiguration(pydantic.BaseModel):
    description: Optional[str] = None


class ConnectionsConfiguration(pydantic.BaseModel):
    add_security_group: Optional[list[PeerConnectionConfiguration]] = None
    allow_default_port_from: Optional[list[PeerConnectionConfiguration]] = None
    allow_default_port_from_any_ipv4: Optional[list[AnyConnectionConfiguration]] = None
    allow_default_port_internally: Optional[list[AnyConnectionConfiguration]] = None
    allow_default_port_to: Optional[list[PeerConnectionConfiguration]] = None
    allow_from: Optional[list[PortConnectionConfiguration]] = None
    allow_from_any_ipv4: Optional[list[AnyConnectionConfiguration]] = None
    allow_internally: Optional[list[AnyConnectionConfiguration]] = None
    allow_to: Optional[list[PortConnectionConfiguration]] = None
    allow_to_any_ipv4: Optional[list[AnyConnectionConfiguration]] = None
    allow_to_default_port: Optional[list[PeerConnectionConfiguration]] = None


class Connectable(pydantic.BaseModel):
    implicit_connections_allowed: Optional[bool] = None
    connections: Optional[ConnectionsConfiguration] = None


class BaseResource(pydantic.BaseModel, abc.ABC):
    # id: str

    @abc.abstractmethod
    def to_construct(self, scope: ManifestStack, id: str) -> constructs.Construct:
        ...


class BucketEncryptionOption(enum.Enum):
    UNENCRYPTED = 'UNENCRYPTED'
    S3_MANAGED = 'S3_MANAGED'


class NotificationKeyFilter(pydantic.BaseModel):
    prefix: Optional[str] = None
    suffix: Optional[str] = None


class BucketNotificationConfiguration(pydantic.BaseModel):
    event: s3.EventType = pydantic.Field(...)
    destination: Grantee = pydantic.Field(...)
    filters: Optional[list[NotificationKeyFilter]] = pydantic.Field(default_factory=list)


class BucketResource(BaseResource):
    versioned: bool = pydantic.Field(False, description='Whether this bucket should have versioning turned on or not. Default: false')
    grant_public_read: bool = pydantic.Field(
        False,
        description="""Allows unrestricted access to objects from this bucket.\nThis method will grant read (“s3:GetObject”) access to all objects (“*”) in the bucket.\nIMPORTANT: This permission allows anyone to perform actions on S3 objects in this bucket, which is useful for when you configure your bucket as a website and want everyone to be able to read objects in the bucket without needing to authenticate.""",
    )
    bucket_name: Optional[str] = pydantic.Field(
        None, description='Physical name of this bucket. Default: - Assigned by CloudFormation (recommended).'
    )
    env_prefix: str = pydantic.Field('', description='The environment variable prefix to use when inserting bucket details')
    website_index_document: Optional[str] = None
    website_error_document: Optional[str] = None
    encryption: BucketEncryptionOption = pydantic.Field(
        BucketEncryptionOption.S3_MANAGED,
        description='How the bucket should be encrypted. By default uses S3-managed encryption. In most cases, you should not change this parameter from the default',
    )
    event_notifications: Optional[list[BucketNotificationConfiguration]] = pydantic.Field(default_factory=list)
    grant_read: Optional[list[Grantee]] = pydantic.Field(default_factory=list)
    grant_read_write: Optional[list[Grantee]] = pydantic.Field(default_factory=list)
    grant_write: Optional[list[Grantee]] = pydantic.Field(default_factory=list)

    # default_access_grants: bool = pydantic.Field(
    #     True,
    #     description='When set to true (the default) read/write access to this bucket will be granted to the IAM roles for other relevant resources in this stack (e.g., services).',
    # )
    # import_from_bucket_name: Optional[str] = pydantic.Field(
    #     None,
    #     description='Import an existing bucket by name, rather than creating a new one (most other options are ignored when this method is used)',
    # )

    def to_construct(self, scope: ManifestStack, id: str) -> s3.Bucket:
        kwargs = {
            'bucket_name': self.bucket_name,
            'versioned': self.versioned,
            'website_error_document': self.website_error_document,
            'website_index_document': self.website_index_document,
        }
        if self.encryption == BucketEncryptionOption.S3_MANAGED:
            kwargs['encryption'] = s3.BucketEncryption.S3_MANAGED
        elif self.encryption == BucketEncryptionOption.UNENCRYPTED:
            kwargs['encryption'] = s3.BucketEncryption.UNENCRYPTED
        bucket = s3.Bucket(
            scope,
            id,
            **kwargs,
        )
        if self.grant_public_read:
            bucket.grant_public_access()

        return bucket


class InstanceTypeConfiguration(pydantic.BaseModel):
    instance_class: ec2.InstanceClass
    instance_size: ec2.InstanceSize

    def to_instance_type(self) -> ec2.InstanceType:
        return ec2.InstanceType.of(instance_class=self.instance_class, instance_size=self.instance_size)


@jsii.implements(ec2.IConnectable)
class RedisCluster(constructs.Construct):
    def __init__(
        self,
        scope: ManifestStack,
        id: str,
        vpc: ec2.IVpc,
        cluster_name: Optional[str] = None,
        cache_node_type: Optional[str] = None,
        num_nodes: int = 1,
        port: int = 6379,
        subnet_ids: Optional[list[str]] = None,
        subnet_type_filter: ec2.SubnetType = ec2.SubnetType.PRIVATE_WITH_NAT,
    ):
        super().__init__(scope, id)
        base_name = aws_cdk.Names.unique_resource_name(construct=self, max_length=120)
        self.elasticache_sg = ec2.SecurityGroup(self, 'elasticache-sg', vpc=vpc, description=f'sg for elasticache cluster {base_name}')
        self._connections = ec2.Connections(default_port=ec2.Port.tcp(port), security_groups=[self.elasticache_sg])
        self.port = port
        if not subnet_ids:
            subnet_ids = vpc.select_subnets(subnet_type=subnet_type_filter).subnet_ids
        if cache_node_type is None:
            cache_node_type = scope.get_default_elasticache_instance_type()
        self.subnet_group = elasticache.CfnSubnetGroup(
            self,
            'subnet-group',
            description='elasticache subnet group',
            subnet_ids=subnet_ids,
            cache_subnet_group_name=base_name + 'subnetgroup',
        )
        self.cache_cluster = elasticache.CfnCacheCluster(
            self,
            id,
            cache_node_type=cache_node_type,
            engine='redis',
            num_cache_nodes=num_nodes,
            cache_subnet_group_name=base_name + 'subnetgroup',
            vpc_security_group_ids=[self.elasticache_sg.security_group_id],
            port=port,
            cluster_name=cluster_name,
        )
        self.cache_cluster.node.add_dependency(self.subnet_group)

    @property
    def connections(self):
        return self._connections


class RedisClusterResource(BaseResource, Connectable):
    port: int = 6379
    num_nodes: int = 1
    subnet_type_filter: Optional[ec2.SubnetType] = None

    def to_construct(self, scope: ManifestStack, id: str) -> RedisCluster:
        vpc = scope.get_vpc_default()
        subnet_ids = scope.get_subnet_ids(vpc, subnet_type=self.subnet_type_filter)
        return RedisCluster(scope=scope, id=id, port=self.port, num_nodes=self.num_nodes, vpc=vpc, subnet_ids=subnet_ids)


class S3OriginOptions(pydantic.BaseModel):
    bucket_id: str = pydantic.Field(
        ..., description='The ID (as declared in your manifest) of the bucket resource you want to use. This is NOT the bucket name!'
    )


class CloudFrontOriginOptions(pydantic.BaseModel):
    s3origin: S3OriginOptions


class CloudFrontBehaviorOptions(pydantic.BaseModel):
    origin: CloudFrontOriginOptions


class CloudFrontDistributionResource(BaseResource):
    domain_names: list[str] = ...
    default_root_object: str = pydantic.Field(
        'index.html',
        description='The object that you want CloudFront to request from your origin (for example, index.html) when a viewer requests the root URL for your distribution.',
    )
    redirect_to_https: bool = pydantic.Field(True, description='Whether to set the viewer protocol policy to redirect HTTP to HTTPS')
    default_behavior: CloudFrontBehaviorOptions = ...
    certificate_id: Optional[str] = pydantic.Field(
        None, description='The certificate to put on the distribution. This certificate must be valid for ALL domain names provided!'
    )

    def to_construct(self, scope: ManifestStack, id: str) -> cloudfront.Distribution:
        # TODO: replace with custom construct to contain distribution and DNS records
        if self.certificate_id:
            certificate = scope.certificates[self.certificate_id]
        else:
            certificate = scope.get_certificate_for_domains(id=id + '-cert', domain_names=self.domain_names)
        bucket_id = self.default_behavior.origin.s3origin.bucket_id

        bucket: s3.Bucket = scope.get_resource(bucket_id)

        # access_identity = cloudfront.OriginAccessIdentity(scope, f'{key}-origin-access-id')

        cf_dist = cloudfront.Distribution(
            scope,
            id,
            default_root_object=self.default_root_object,
            default_behavior=cloudfront.BehaviorOptions(
                origin=cloudfront_origins.S3Origin(
                    bucket,
                    # origin_access_identity=access_identity
                ),
                viewer_protocol_policy=cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
                allowed_methods=cloudfront.AllowedMethods.ALLOW_GET_HEAD,
            ),
            domain_names=self.domain_names,
            certificate=certificate,
        )
        # grant = bucket.grant_public_access()
        for index, domain in enumerate(self.domain_names, start=1):
            route53.ARecord(
                scope,
                f'{id}-dns-{index}',
                record_name=domain,
                zone=scope._get_hosted_zone_for_domain(domain),
                target=route53.RecordTarget.from_alias(route53_targets.CloudFrontTarget(cf_dist)),
            )
        aws_cdk.CfnOutput(scope, f'{id}-distribution-id', value=cf_dist.distribution_id)

        return cf_dist


PostgresEngineVersion = enum.Enum(
    'PostgresEngineVersion',
    {name: name for name in dir(rds.PostgresEngineVersion) if name.startswith('VER_')},
)

MysqlEngineVersion = enum.Enum('MysqlEngineVersion', {name: name for name in dir(rds.MysqlEngineVersion) if name.startswith('VER_')})

MariaDbEngineVersion = enum.Enum(
    'MariaDbEngineVersion',
    {name: name for name in dir(rds.MariaDbEngineVersion) if name.startswith('VER_')},
)


class EngineDefinition(pydantic.BaseModel):
    postgres: Optional[PostgresEngineVersion] = None
    mysql: Optional[MysqlEngineVersion] = None
    mariadb: Optional[MariaDbEngineVersion] = None

    def to_engine(self) -> rds.DatabaseInstanceEngine | rds.IInstanceEngine:
        engines = [e for e in (self.postgres, self.mysql, self.mariadb) if e is not None]
        assert len(engines) == 1, f'Exactly one engine must be defined, got {len(engines)}'
        if self.postgres:
            return rds.DatabaseInstanceEngine.postgres(version=getattr(rds.PostgresEngineVersion, self.postgres.value))
        elif self.mysql:
            return rds.DatabaseInstanceEngine.mysql(version=getattr(rds.MysqlEngineVersion, self.mysql.value))
        elif self.mariadb:
            return rds.DatabaseInstanceEngine.maria_db(version=getattr(rds.MariaDbEngineVersion, self.mariadb.value))
        else:
            raise Exception('This is a bug, please report')


class RDSDatabaseResource(BaseResource, Connectable):
    engine: EngineDefinition = pydantic.Field(..., description='The database engine to use')
    initial_size_gb: int = pydantic.Field(
        20, description='The initial disk size for the database. Default 20GB (the minimum for most engines)'
    )
    max_disk_size_gb: Optional[int] = pydantic.Field(
        None, description='The max disk size to which the database will be allowed to autoexpand'
    )
    database_name: str = pydantic.Field('mydb', description='The name of the initial database to create')
    instance_type: Optional[InstanceTypeConfiguration] = pydantic.Field(
        None, description='The class/size of instance. If not specified, uses the default from the environment provider'
    )
    env_prefix: Optional[str] = pydantic.Field(None)

    def to_construct(self, scope: ManifestStack, id: str) -> rds.DatabaseInstance:
        instance_type = self.instance_type or scope.get_default_database_instance_size()

        db = rds.DatabaseInstance(
            scope,
            id,
            storage_encrypted=True,
            engine=self.engine.to_engine(),
            allocated_storage=self.initial_size_gb,
            database_name=self.database_name,
            instance_type=instance_type,
            max_allocated_storage=self.max_disk_size_gb,
            removal_policy=aws_cdk.RemovalPolicy.SNAPSHOT,
            vpc=scope.get_vpc_default(),
        )
        return db


class SecretsManagerSecretResource(BaseResource):
    from_secret_name: Optional[str] = None

    def to_construct(self, scope: ManifestStack, id: str) -> secretsmanager.ISecret:
        ...


class SecretDefinition(pydantic.BaseModel):
    secret_id: str
    field: str


class FargateContainerDefinition(pydantic.BaseModel):
    port: Optional[int] = pydantic.Field(
        None,
        description='The port inside the container that should be exposed. This option is only used by load-balanced services and only applies to the first defined container.',
    )
    ecr_repository: Optional[str] = pydantic.Field(
        None, description='The name of the ECR repository containing the image to be used for this container. This must already exist'
    )
    initial_default_tag: Optional[str] = pydantic.Field(
        None,
        description='The tag in the ECR repo to use. Defaults to the environment name. In most cases, you should not change this from the default value',
    )
    environment_variables: Optional[dict[str, str]] = pydantic.Field(
        default_factory=dict, description='Add environment variables to the container'
    )
    secrets: Optional[dict[str, SecretDefinition]] = pydantic.Field(
        default_factory=dict, description='SecretsManager secrets to add to service environment variables'
    )
    command: Optional[list[str]] = pydantic.Field(None, description='The command passed to the container on start. E.g., ["yarn", "run"]')
    memory_limit_mib: Optional[int] = pydantic.Field(None, description='Memory limit in megabytes')


class ALBServiceHealthcheckOptions(pydantic.BaseModel):
    path: str = '/healthz'
    unhealthy_threshold_count: Optional[int] = pydantic.Field(
        None, description='The number of failed health checks required before the container is considered unhealthy'
    )
    grace_period_seconds: Optional[int] = pydantic.Field(
        None,
        description='Configure an grace period in seconds in which healthchecks will be allowed to fail when the container initially starts up (useful for services with long startup periods)',
    )


class FargateServiceResource(BaseResource, Connectable):
    containers: dict[str, FargateContainerDefinition] = ...
    initial_desired_count: Optional[int] = pydantic.Field(
        None,
        description='The number of instances that should initially be started on first deployment. Most of the time, you should not need to change this. Actual running count in most cases is determined by scaling policy',
    )
    service_name: str = pydantic.Field('', description='The service name')

    def to_construct(self, scope: ManifestStack, id: str) -> ecs.FargateService:
        worker_taskdef = ecs.FargateTaskDefinition(scope, f'{id}-taskdef', family=f'{scope.stack_name}-{id}')
        for container_name, container in self.containers.items():
            # TODO: move this to an aspect
            # db_secrets = {}
            # for db_id, db in scope.databases.items():
            #     db_definition: RDSDatabaseResource = scope.definitions[db_id]  # noqa
            #     # TODO add narrowing function
            #     if db_definition.env_prefix:
            #         env_prefix = db_definition.env_prefix
            #     else:
            #         env_prefix = db_id.upper().replace('-', '_')
            #     db_secrets[f'{env_prefix}_PASSWORD'] = ecs.Secret.from_secrets_manager(db.secret, field='password')
            #     db_secrets[f'{env_prefix}_USERNAME'] = ecs.Secret.from_secrets_manager(db.secret, field='username')
            #     db_secrets[f'{env_prefix}_HOST'] = ecs.Secret.from_secrets_manager(db.secret, field='host')
            #     db_secrets[f'{env_prefix}_DB_NAME'] = ecs.Secret.from_secrets_manager(db.secret, field='dbname')

            secrets = {}

            for env_name, secret_def in container.secrets.items():
                sm_secret = scope.get_resource(secret_def.secret_id)
                secrets[env_name] = ecs.Secret.from_secrets_manager(sm_secret, field=secret_def.field)

            env = container.environment_variables
            repository = ecr.Repository.from_repository_name(scope, f'{id}-{container_name}', repository_name=container.ecr_repository)
            tag = container.initial_default_tag or scope.environment_name
            # worker_taskdef.task_role.add_to_policy(environment.get_parameter_policy_statement())
            worker_taskdef.add_container(
                container_name,
                image=ecs.ContainerImage.from_ecr_repository(
                    repository=repository,
                    tag=tag,
                ),
                command=container.command,
                logging=ecs.LogDriver.aws_logs(
                    stream_prefix=f'{id}-{container_name}', log_retention=scope.get_default_service_log_retention_period()
                ),
                secrets={**secrets},
                environment=env,
            )

        # self.backend_taskdef.node.add_dependency(*self.custom_secure_string_resources)
        worker_service = ecs.FargateService(
            scope,
            id,
            platform_version=ecs.FargatePlatformVersion.VERSION1_4,
            cluster=scope.get_ecs_cluster_default(is_fargate=True),
            desired_count=self.initial_desired_count,
            enable_ecs_managed_tags=True,
            task_definition=worker_taskdef,
            service_name=self.service_name,
        )

        # TODO: implement as aspect
        # for db_id, db in scope.databases.items():
        #     db.connections.allow_default_port_from(worker_service)

        # for redis_cluster_id, cluster in scope.redis_clusters.items():
        #     cluster.connections.allow_from(
        #         worker_service,
        #         port_range=ec2.Port.tcp(cluster.port),
        #         description=f'allows {id} service to talk to elasticache',
        #     )
        return worker_service


class CpuUtilizationScalingConfiguration(pydantic.BaseModel):
    scale_in_cooldown_seconds: int = pydantic.Field(
        300, description='Period after a scale in activity completes before another scale in activity can start'
    )
    scale_out_cooldown_seconds: int = pydantic.Field(
        120, description='Period after a scale out activity completes before another scale out activity can start'
    )
    target_utilization_percent: int = pydantic.Field(
        ..., description='The target value for CPU utilization across all tasks in the service'
    )
    disable_scale_in: Optional[bool] = pydantic.Field(
        None,
        description='Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won’t remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. Default: false',
    )


class MemoryUtilizationScalingConfiguration(pydantic.BaseModel):
    scale_in_cooldown_seconds: int = pydantic.Field(
        300, description='Period after a scale in activity completes before another scale in activity can start'
    )
    scale_out_cooldown_seconds: int = pydantic.Field(
        120, description='Period after a scale out activity completes before another scale out activity can start'
    )
    target_utilization_percent: int = pydantic.Field(
        ..., description='The target value for memory utilization across all tasks in the service.'
    )
    disable_scale_in: bool = pydantic.Field(
        None,
        description='Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won’t remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. Default: false',
    )


class RequestCountScalingConfiguration(pydantic.BaseModel):
    requests_per_target: int | float = pydantic.Field(..., description='The number of ALB requests per target')
    disable_scale_in: bool = pydantic.Field(
        None,
        description='Indicates whether scale in by the target tracking policy is disabled. If the value is true, scale in is disabled and the target tracking policy won’t remove capacity from the scalable resource. Otherwise, scale in is enabled and the target tracking policy can remove capacity from the scalable resource. Default: false',
    )
    scale_in_cooldown_seconds: int = pydantic.Field(
        300, description='Period after a scale in activity completes before another scale in activity can start'
    )
    scale_out_cooldown_seconds: int = pydantic.Field(
        120, description='Period after a scale out activity completes before another scale out activity can start'
    )


class AutoScalingConfiguration(pydantic.BaseModel):
    min_capacity: int = pydantic.Field(2, description='Minimum number of instances allowed')
    max_capacity: int = pydantic.Field(..., description='Maximum number of instances allowed')
    on_cpu_utilization: Optional[CpuUtilizationScalingConfiguration] = None
    on_memory_utilization: Optional[MemoryUtilizationScalingConfiguration] = None
    on_request_count: Optional[RequestCountScalingConfiguration] = None
    # TODO: support step scaling, custom metrics


class ApplicationLoadBalancedFargateServiceResource(BaseResource, Connectable):
    containers: dict[str, FargateContainerDefinition] = ...
    desired_count: Optional[int] = pydantic.Field(
        None,
        description='The number of instances that should initially be started on first deployment. Most of the time, you should not need to change this. Actual running count in most cases is determined by scaling policy',
    )
    service_name_suffix: str = pydantic.Field('', description='An additional string added to the ')
    additional_domain_names: Optional[list[str]] = pydantic.Field(
        None,
        description='Additional domain names to point to the ALB via CNAME records. By default, only an auto-generated A Name is provided',
    )
    domain_name: Optional[str] = pydantic.Field(
        None,
        description='The domain name for the service. By default (recommended) a domain name is generated automatically in the format of `{resource-id}-{region}-{environment}-{apex}.{tld}`',
    )
    public_loadbalancer: bool = pydantic.Field(
        True,
        description='Whether or not to allow access to the load balancer from the public internet. Set to False if this service should not be exposed to the internet (internal only service) Default true.',
    )
    use_private_subnet: bool = pydantic.Field(
        True,
        description='Whether the service will be placed in the VPC\'s private subnet. Note: this does NOT affect the ability for the service to be reached from the public internet. IMPORTANT: most of the time, you should not change this default value!',
    )
    health_check_options: Optional[ALBServiceHealthcheckOptions] = None
    minimum_healthy_percent: int = pydantic.Field(
        50,
        description='The minimum percentage of healthy instances required for the service to be considered healthy. ECS deployment and scaling activity will obey this setting!',
    )
    max_healthy_percent: int = pydantic.Field(
        200,
        description='The maximum percentage of healthy instances allowed. Default is 200 (to allow new containers for deployments without needing to shut down any of the previous version containers first)',
    )
    autoscaling_config: Optional[AutoScalingConfiguration] = pydantic.Field(None, description='Autoscaling configuration for the service')

    def to_construct(self, scope: ManifestStack, id: str) -> ecs_patterns.ApplicationLoadBalancedFargateService:
        service_taskdef = ecs.FargateTaskDefinition(scope, f'{id}-taskdef', family=f'{scope.stack_name}-{id}')
        for container_name, container in self.containers.items():
            # TODO: move to aspect
            # db_secrets = {}
            # for db_id, db in scope.databases.items():
            #     db_definition: RDSDatabaseResource = scope.definitions[db_id]  # noqa
            #     # TODO add narrowing function
            #     if db_definition.env_prefix:
            #         env_prefix = db_definition.env_prefix
            #     else:
            #         env_prefix = db_id.upper().replace('-', '_')
            #     db_secrets[f'{env_prefix}_PASSWORD'] = ecs.Secret.from_secrets_manager(db.secret, field='password')
            #     db_secrets[f'{env_prefix}_USERNAME'] = ecs.Secret.from_secrets_manager(db.secret, field='username')
            #     db_secrets[f'{env_prefix}_HOST'] = ecs.Secret.from_secrets_manager(db.secret, field='host')
            #     db_secrets[f'{env_prefix}_DB_NAME'] = ecs.Secret.from_secrets_manager(db.secret, field='dbname')

            secrets = {}

            for env_name, secret_def in container.secrets.items():
                sm_secret = scope.get_resource(secret_def.secret_id)
                secrets[env_name] = ecs.Secret.from_secrets_manager(sm_secret, field=secret_def.field)

            env = container.environment_variables
            repository = ecr.Repository.from_repository_name(scope, f'{id}-{container_name}-repo', repository_name=container.ecr_repository)
            tag = container.initial_default_tag or scope.environment_name
            # service_taskdef.task_role.add_to_policy(environment.get_parameter_policy_statement())
            service_container = service_taskdef.add_container(
                container_name,
                image=ecs.ContainerImage.from_ecr_repository(
                    repository=repository,
                    tag=tag,
                ),
                command=container.command,
                logging=ecs.LogDriver.aws_logs(
                    stream_prefix=f'{id}-{container_name}', log_retention=scope.get_default_service_log_retention_period()
                ),
                secrets={**secrets},
                environment=env,
            )
            # TODO: support more than one port
            if container.port:
                service_container.add_port_mappings(*[ecs.PortMapping(container_port=port) for port in [container.port]])

        # TODO: define networks to be exportable/importable
        # backend_service_sg = ec2.SecurityGroup(
        #     self, "servicesg", allow_all_outbound=True, vpc=self.infra_stack.vpc
        # )
        if self.domain_name is None:
            stack_name = scope.stack_name
            default_hosted_zone_name = scope.get_default_hosted_zone_name()
            domain_name = f'{stack_name}-{id}.{default_hosted_zone_name}'
            print(domain_name)
        else:
            domain_name = self.domain_name

        load_balanced_service = ecs_patterns.ApplicationLoadBalancedFargateService(
            scope,
            id,
            platform_version=ecs.FargatePlatformVersion.VERSION1_4,
            domain_name=domain_name,
            domain_zone=scope._get_hosted_zone_for_domain(domain_name),
            protocol=elbv2.ApplicationProtocol.HTTPS,
            redirect_http=True,
            task_definition=service_taskdef,
            desired_count=self.desired_count,
            min_healthy_percent=self.minimum_healthy_percent,
            max_healthy_percent=self.max_healthy_percent,
            circuit_breaker=ecs.DeploymentCircuitBreaker(rollback=True),
            cluster=scope.get_ecs_cluster_default(is_fargate=True),  # TODO: allow custom cluster definition in construct
            enable_ecs_managed_tags=True,
            service_name=f'{scope.manifest.name}-{id}-{scope.environment_name}',
            health_check_grace_period=aws_cdk.Duration.seconds(self.health_check_options.grace_period_seconds)
            if self.health_check_options and self.health_check_options.grace_period_seconds
            else None,
        )

        if self.health_check_options:
            load_balanced_service.target_group.configure_health_check(
                enabled=True,
                path=self.health_check_options.path,
                unhealthy_threshold_count=self.health_check_options.unhealthy_threshold_count,
            )
        else:
            load_balanced_service.target_group.configure_health_check(enabled=True, path='/healthz', unhealthy_threshold_count=10)
        if self.autoscaling_config is not None:
            scaling = load_balanced_service.service.auto_scale_task_count(
                max_capacity=self.autoscaling_config.max_capacity,
                min_capacity=self.autoscaling_config.min_capacity,
            )
            if self.autoscaling_config.on_cpu_utilization:
                scaling.scale_on_cpu_utilization(
                    'autoscale-cpu',
                    target_utilization_percent=self.autoscaling_config.on_cpu_utilization.target_utilization_percent,
                    scale_in_cooldown=aws_cdk.Duration.seconds(self.autoscaling_config.on_cpu_utilization.scale_in_cooldown_seconds),
                    scale_out_cooldown=aws_cdk.Duration.seconds(self.autoscaling_config.on_cpu_utilization.scale_out_cooldown_seconds),
                )
            if self.autoscaling_config.on_request_count:
                scaling.scale_on_request_count(
                    'autoscale-request-count',
                    requests_per_target=self.autoscaling_config.on_request_count.requests_per_target,
                    scale_in_cooldown=self.autoscaling_config.on_request_count.scale_in_cooldown_seconds,
                    scale_out_cooldown=self.autoscaling_config.on_request_count.scale_out_cooldown_seconds,
                )

        # load_balanced_service.task_definition.task_role.add_to_policy(environment.get_parameter_policy_statement())
        return load_balanced_service


class DeadLetterQueueConfiguration(pydantic.BaseModel):
    max_receive_count: int | float = pydantic.Field(
        ..., description='The number of times a message can be unsuccesfully dequeued before being moved to the dead-letter queue.'
    )
    queue_id: str = pydantic.Field(..., description='Resource id of the queue to use for DLQ')


class SQSQueueResource(BaseResource):
    content_based_deduplication: Optional[bool] = pydantic.Field(
        None,
        description="""Specifies whether to enable content-based deduplication. During the deduplication interval (5 minutes), Amazon SQS treats messages that are sent with identical content (excluding attributes) as duplicates and delivers only one copy of the message. If you don’t enable content-based deduplication and you want to deduplicate messages, provide an explicit deduplication ID in your SendMessage() call. (Only applies to FIFO queues.) Default: false""",
    )
    data_key_reuse_seconds: Optional[int] = pydantic.Field(
        None,
        description="""The length of time that Amazon SQS reuses a data key before calling KMS again. The value must be an integer between 60 (1 minute) and 86,400 (24 hours). The default is 300 (5 minutes). Default: Duration.minutes(5)""",
    )
    dead_letter_queue: Optional[DeadLetterQueueConfiguration] = pydantic.Field(
        None,
        description="""Send messages to this queue if they were unsuccessfully dequeued a number of times. Default: no dead-letter queue""",
    )
    deduplication_scope: Optional[aws_cdk.aws_sqs.DeduplicationScope] = pydantic.Field(
        None,
        description="""For high throughput for FIFO queues, specifies whether message deduplication occurs at the message group or queue level. (Only applies to FIFO queues.) Default: DeduplicationScope.QUEUE""",
    )
    delivery_delay_seconds: Optional[int] = pydantic.Field(
        None,
        description="""The time in seconds that the delivery of all messages in the queue is delayed. You can specify an integer value of 0 to 900 (15 minutes). The default value is 0. Default: 0""",
    )
    encryption: Optional[aws_cdk.aws_sqs.QueueEncryption] = pydantic.Field(
        None,
        description="""Whether the contents of the queue are encrypted, and by what type of key. Be aware that encryption is not available in all regions, please see the docs for current availability details. Default: SQS_MANAGED (SSE-SQS) for newly created queues""",
    )
    # encryption_master_key: Optional[aws_cdk.aws_kms.IKey] = pydantic.Field(
    #     None,
    #     description="""External KMS key to use for queue encryption. Individual messages will be encrypted using data keys. The data keys in turn will be encrypted using this key, and reused for a maximum of dataKeyReuseSecs seconds. If the ‘encryptionMasterKey’ property is set, ‘encryption’ type will be implicitly set to “KMS”. Default: If encryption is set to KMS and not specified, a key will be created.""",
    # )
    enforce_ssl: Optional[bool] = pydantic.Field(None, description="""Enforce encryption of data in transit. Default: false""")
    fifo: Optional[bool] = pydantic.Field(
        None,
        description="""Whether this a first-in-first-out (FIFO) queue. Default: false, unless queueName ends in ‘.fifo’ or ‘contentBasedDeduplication’ is true.""",
    )
    fifo_throughput_limit: Optional[aws_cdk.aws_sqs.FifoThroughputLimit] = pydantic.Field(
        None,
        description="""For high throughput for FIFO queues, specifies whether the FIFO queue throughput quota applies to the entire queue or per message group. (Only applies to FIFO queues.) Default: FifoThroughputLimit.PER_QUEUE""",
    )
    max_message_size_bytes: Union[int, float, None] = pydantic.Field(
        ...,
        description="""The limit of how many bytes that a message can contain before Amazon SQS rejects it. You can specify an integer value from 1024 bytes (1 KiB) to 262144 bytes (256 KiB). The default value is 262144 (256 KiB). Default: 256KiB""",
    )
    queue_name: Optional[str] = pydantic.Field(
        None,
        description="""A name for the queue. If specified and this is a FIFO queue, must end in the string ‘.fifo’. Default: CloudFormation-generated name""",
    )
    receive_message_wait_time_seconds: Optional[int] = pydantic.Field(
        None,
        description="""Default wait time for ReceiveMessage calls. Does not wait if set to 0, otherwise waits this amount of seconds by default for messages to arrive. For more information, see Amazon SQS Long Poll. Default: 0""",
    )
    removal_policy: Optional[aws_cdk.RemovalPolicy] = pydantic.Field(
        None,
        description="""Policy to apply when the queue is removed from the stack. Even though queues are technically stateful, their contents are transient and it is common to add and remove Queues while rearchitecting your application. The default is therefore DESTROY""",
    )
    retention_period_seconds: Optional[int] = pydantic.Field(
        None,
        description="""The number of seconds that Amazon SQS retains a message. You can specify an integer value from 60 seconds (1 minute) to 1209600 seconds (14 days). The default value is 345600 seconds (4 days). Default: Duration.days(4)""",
    )
    visibility_timeout_seconds: Optional[int] = pydantic.Field(
        None,
        description="""Timeout of processing a single message. After dequeuing, the processor has this much time to handle the message and delete it from the queue before it becomes visible again for dequeueing by another processor. Values must be from 0 to 43200 seconds (12 hours). If you don’t specify a value, AWS CloudFormation uses the default value of 30 seconds. Default: Duration.seconds(30)""",
    )
    grant_purge: Optional[list[Grantee]] = pydantic.Field(default_factory=list)
    grant_send_messages: Optional[list[Grantee]] = pydantic.Field(default_factory=list)
    grant_consume_messages: Optional[list[Grantee]] = pydantic.Field(default_factory=list)
    grant_full_access: Optional[list[Grantee]] = pydantic.Field(default_factory=list)

    def to_construct(self, scope: ManifestStack, id) -> sqs.Queue:
        data_key_reuse = aws_cdk.Duration.seconds(self.data_key_reuse_seconds) if self.data_key_reuse_seconds is not None else None
        delivery_delay = aws_cdk.Duration.seconds(self.delivery_delay_seconds) if self.delivery_delay_seconds is not None else None
        receive_message_wait_time = (
            aws_cdk.Duration.seconds(self.receive_message_wait_time_seconds) if self.receive_message_wait_time_seconds is not None else None
        )
        retention_period = aws_cdk.Duration.seconds(self.retention_period_seconds) if self.retention_period_seconds is not None else None
        visibility_timeout = (
            aws_cdk.Duration.seconds(self.visibility_timeout_seconds) if self.visibility_timeout_seconds is not None else None
        )

        if self.dead_letter_queue:
            try:
                q = scope.get_resource(self.dead_letter_queue.queue_id)
            except KeyError as e:
                raise CreationDeferredException(
                    f'referenced DLQ {self.dead_letter_queue.queue_id!r} does not exist yet. Deferring until it is created.'
                ) from e
            dead_letter_queue = sqs.DeadLetterQueue(max_receive_count=self.dead_letter_queue.max_receive_count, queue=q)
        else:
            dead_letter_queue = None

        queue = sqs.Queue(
            scope,
            id,
            content_based_deduplication=self.content_based_deduplication,
            dead_letter_queue=dead_letter_queue,
            deduplication_scope=self.deduplication_scope,
            encryption=self.encryption,
            enforce_ssl=self.enforce_ssl,
            fifo=self.fifo,
            fifo_throughput_limit=self.fifo_throughput_limit,
            max_message_size_bytes=self.max_message_size_bytes,
            queue_name=self.queue_name,
            removal_policy=self.removal_policy,
            data_key_reuse=data_key_reuse,
            delivery_delay=delivery_delay,
            receive_message_wait_time=receive_message_wait_time,
            retention_period=retention_period,
            visibility_timeout=visibility_timeout,
        )

        return queue


# class SQSDeadLetterQueueResource(BaseResource):
#     def to_construct(self, scope: ManifestStack, id) -> sqs.DeadLetterQueue:
#         ...


class SNSTopicResource(BaseResource):
    def to_construct(self, scope: ManifestStack, id: str) -> sns.Topic:
        ...


# class CertificateResource(BaseResource):
#     domain_name: str
#     subject_alternative_names: Optional[list[str]] = None
#
#     def to_construct(self, scope: ManifestStack, id: str) -> certmanager.Certificate:
#         ...


class ResourcesDefinition(pydantic.BaseModel):
    buckets: Optional[dict[str, BucketResource]] = pydantic.Field(default_factory=dict)
    redis_clusters: Optional[dict[str, RedisClusterResource]] = pydantic.Field(default_factory=dict)
    cloudfront_distributions: Optional[dict[str, CloudFrontDistributionResource]] = pydantic.Field(default_factory=dict)
    databases: Optional[dict[str, RDSDatabaseResource]] = pydantic.Field(default_factory=dict)
    application_loadbalanced_fargate_services: Optional[dict[str, ApplicationLoadBalancedFargateServiceResource]] = pydantic.Field(
        default_factory=dict
    )
    fargate_services: Optional[dict[str, FargateServiceResource]] = pydantic.Field(default_factory=dict)
    sqs_queues: Optional[dict[str, SQSQueueResource]] = pydantic.Field(default_factory=dict)


class EnvironmentDefinition(pydantic.BaseModel):
    name: str
    regions: Optional[list[str]] = None
    account: Optional[str] = None
    provider_config: Optional[dict[str, Any]] = None


class Manifest(pydantic.BaseModel):
    version: ManifestVersion = pydantic.Field(
        ..., description='The manifest version. Ensures major behaviors remain consistent between tool updates.'
    )
    name: str = pydantic.Field(
        ...,
        description='A short name. This will be used as the stack name as well as for automatic naming of certain resources. Must be unique!',
    )
    resources: dict[str, ResourcesDefinition]
    environments: Optional[list[Union[str, EnvironmentDefinition]]] = pydantic.Field(
        None,
        description='The environments that are available for deployment. IMPORTANT: removing environments will NOT destroy the stacks. Before removing an entry from this list, destroy the stack FIRST.',
    )

    regions: Optional[list[str]] = pydantic.Field(
        None,
        description='The regions in which to create your stack(s). By default, this list is applied to all environments that do not specify a region list',
    )

    account: Optional[str] = pydantic.Field(
        None,
        description='The default account to use for deployments',
    )

    github_repositories: Optional[list[str]] = pydantic.Field(
        None,
        description='Allows listed github repos to deploy resources in this manifest. Repositories should be in the format of `Owner/Repo`',
    )
    tags: Optional[dict[str, dict[str, str]]] = pydantic.Field(None, description='Tags that will be added to all resources in the stack.')
    implicit_connections: bool = False

    provider_class: Optional[str] = pydantic.Field(None, description='The environment provider class to use')

    provider_config: dict[str, Any] = pydantic.Field(description='keyword arguments to pass to the provider', default_factory=dict)
    integrations: Optional[dict[str, dict[str, Any]]] = None

    def get_provider_class(self) -> Type[EnvironmentProvider]:
        if self.provider_class is None:
            return EnvironmentProvider
        else:
            module_name, class_name = self.provider_class.rsplit('.', 1)
            mod = importlib.import_module(module_name)
            klass = getattr(mod, class_name)
            assert issubclass(klass, EnvironmentProvider)
            return klass


@jsii.implements(aws_cdk.IAspect)
class ImplicitConnectionsConfigurator:
    def __init__(self, stack: ManifestStack):
        self.stack = stack

    @property
    def _seen_connectables(self):
        return self.stack._seen_connectables

    def visit(self, node):
        # if isinstance(node, elbv2.ApplicationLoadBalancer):
        #     return
        # if isinstance(node, elbv2.ApplicationListener):
        #     return

        if isinstance(node, ec2.SecurityGroup):
            return  # Don't work with security groups directly.
        if hasattr(node, 'connections') and isinstance(node.connections, ec2.Connections) and node.connections:
            for connectable in self._seen_connectables:
                if node.connections.default_port:
                    node.connections.allow_default_port_from(connectable)
                for c2 in self._seen_connectables:
                    if c2.connections.default_port:
                        c2.connections.allow_default_port_from(node)
            self._seen_connectables.add(node)


@jsii.implements(aws_cdk.IAspect)
class ImplicitReadWriteGrants:
    def visit(self, node) -> None:
        ...


class StackDefaults:
    def __init__(self, vpc: Optional[ec2.IVpc] = None):
        self.vpc: Optional[ec2.IVpc] = vpc


class ManifestStack(aws_cdk.Stack):
    def __init__(
        self,
        scope: aws_cdk.App,
        provider: EnvironmentProvider,
        manifest: Manifest,
        defaults: Optional[StackDefaults] = None,
        **kwargs,
    ):
        env = aws_cdk.Environment(account=provider.account, region=provider.region)

        if 'env' in kwargs:
            raise ValueError('env cannot be provided to ManifestStack. Environment is defined by the environment provider.')
        if provider.environment_name == 'default':
            raise ValueError('default is a reserved name')

        id = f'{manifest.name}-{provider.region}-{provider.environment_name}'
        super().__init__(scope, id, env=env, stack_name=id)
        self.defaults = defaults
        self.manifest = manifest
        self._env = env
        self._provider = provider
        self.integrations = {}
        self.definitions: dict[str, BaseResource] = {}
        self.resources: dict[str, constructs.Construct] = {}
        self._hz_lookup_cache: dict[str, route53.IHostedZone] = {}
        self._default_fargate_cluster = None
        self._seen_connectables = set()
        self._initialize_integrations()
        self._create_resources()
        self._configure_resources()
        self._configure_connections()
        self._configure_integrations()

    @functools.singledispatchmethod
    def configure_resource(self, resource: Any, definition: BaseResource) -> bool:
        # TODO: defer to stack for default implementations
        return False

    @configure_resource.register
    def configure_s3_resource(self, resource: s3.Bucket, definition: BucketResource):
        # configure notifications
        bucket = resource
        if definition.grant_public_read:
            bucket.grant_public_access()
        for event_configuration in definition.event_notifications:
            filters = []
            if event_configuration.filters:
                for filterconfig in event_configuration.filters:
                    filters.append(s3.NotificationKeyFilter(**filterconfig))

            dest = self.get_resource(event_configuration.destination.resource_id)
            bucket.add_event_notification(event=event_configuration.event, dest=dest, *filters)
        for grantee in definition.grant_write:
            grantable = self.get_resource(grantee.resource_id)
            bucket.grant_write(grantable)
        for grantee in definition.grant_read_write:
            grantable = self.get_resource(grantee.resource_id)
            bucket.grant_read_write(grantable)
        for grantee in definition.grant_read:
            grantable = self.get_resource(grantee.resource_id)
            bucket.grant_read(grantable)

    @configure_resource.register
    def configure_sqs_queue(self, resource: sqs.Queue, definition: SQSQueueResource):
        queue = resource
        for grantee in definition.grant_full_access:
            grantable = self.get_resource(grantee.resource_id)
            queue.grant_purge(grantable)
            queue.grant_consume_messages(grantable)
            queue.grant_send_messages(grantable)

        for grantee in definition.grant_purge:
            grantable = self.get_resource(grantee.resource_id)
            queue.grant_purge(grantable)
        for grantee in definition.grant_consume_messages:
            grantable = self.get_resource(grantee.resource_id)
            queue.grant_consume_messages(grantable)
        for grantee in definition.grant_send_messages:
            grantable = self.get_resource(grantee.resource_id)
            queue.grant_send_messages(grantable)

    def _configure_resources(self):
        for id, definition in self.definitions.items():
            resource = self.resources[id]
            self.configure_resource(resource, definition)

    def get_vpc_default(self):
        if self.defaults is not None:
            default_vpc = self.defaults.vpc
            if default_vpc is not None:
                return default_vpc
        return self._provider.get_vpc_default(scope=self)

    def get_default_service_log_retention_period(self) -> aws_logs.RetentionDays:
        return self._provider.get_default_service_log_retention_period()

    def get_default_database_instance_size(self) -> str | ec2.InstanceType:
        return self._provider.get_default_database_instance_size()

    def get_default_elasticache_instance_type(self) -> str:
        return self._provider.get_default_elasticache_instance_type()

    def get_ecs_cluster_default(self, is_fargate: bool) -> ecs.ICluster:
        cluster = self._provider.get_ecs_cluster_default(is_fargate=is_fargate)
        if cluster is not None:
            return cluster
        else:
            if is_fargate:
                if self._default_fargate_cluster:
                    return self._default_fargate_cluster
                else:
                    self._default_fargate_cluster = self._make_fargate_cluster(
                        id='fargate-default', cluster_name=f'{self.manifest.name}-{self.environment_name}-default'
                    )
                    return self._default_fargate_cluster
            else:
                raise NotImplementedError("Haven't gotten to this yet")

    def _make_fargate_cluster(self, id, cluster_name, vpc: Optional[ec2.IVpc] = None) -> ecs.ICluster:
        # XXX factor out once cluster resources are supported

        if vpc is None:
            vpc = self.get_vpc_default()

        return ecs.Cluster(self, id, vpc=vpc, container_insights=True, cluster_name=cluster_name)

    def get_subnet_ids(self, vpc: Optional[ec2.IVpc] = None, subnet_type: Optional[ec2.SubnetType] = None) -> list[str]:
        if vpc is None:
            raise ValueError('no vpc provided')
        if subnet_type is None:
            subnet_type = ec2.SubnetType.PRIVATE_WITH_NAT
        return vpc.select_subnets(subnet_type=subnet_type).subnet_ids

    def get_default_database_instance_type(self) -> ec2.InstanceType:
        return self._provider.get_default_database_instance_type()

    def _get_hosted_zone_for_domain(self, domain_name: str):
        apex = '.'.join(domain_name.split('.')[-2:])
        if apex in self._hz_lookup_cache:
            return self._hz_lookup_cache[apex]
        zone = route53.HostedZone.from_lookup(self, apex + '-hosted-zone', domain_name=apex)
        self._hz_lookup_cache[apex] = zone
        return zone

    def get_default_hosted_zone_name(self) -> str:
        return self._provider.get_default_hosted_zone_name()

    def _get_validation_for_domains(self, domain_names: list[str]):
        apex_domains = dict()
        for name in domain_names:
            apex = '.'.join(name.split('.')[-2:])
            if apex in apex_domains:
                apex_domains[apex].append(name)
            else:
                apex_domains[apex] = [name]

        if len(apex_domains) == 1:
            apex = list(apex_domains)[0]
            return certmanager.CertificateValidation.from_dns(hosted_zone=self._get_hosted_zone_for_domain(domain_name=apex))
        else:
            domain_map = {}
            for name in domain_names:
                zone = self._get_hosted_zone_for_domain(name)
                domain_map[name] = zone
            return certmanager.CertificateValidation.from_dns_multi_zone(hosted_zones=domain_map)

    def get_certificate_for_domains(self, id: str, domain_names: list[str]) -> certmanager.ICertificate:
        cert = certmanager.Certificate(
            self,
            id,
            domain_name=domain_names[0],
            subject_alternative_names=domain_names[1:] or None,
            validation=self._get_validation_for_domains(domain_names),
        )
        return cert

    @property
    def environment_name(self) -> str:
        return self._provider.environment_name

    # @property
    # def account(self) -> str:
    #     return self._provider.account

    @property
    def region(self) -> str:
        return self._provider.region

    def _configure_connections(self):
        connectable_definitions: dict[str, Connectable] = {}
        for resource_id, definition in self.definitions.items():
            if isinstance(definition, Connectable):
                connectable_definitions[resource_id] = definition
        for cid in connectable_definitions:
            definition = connectable_definitions[cid]
            resource = self.resources[cid]  # type: ignore
            if not hasattr(resource, 'connections'):
                warnings.warn(
                    f'requested connection configuration for resource {resource!r} but does not implement the connectable interface. Skipping.'
                )
                continue

            definition_connections = definition.connections
            resource_connections = resource.connections
            if not definition_connections:
                continue
            for method_name, configurations_list in definition_connections.dict().items():
                if not configurations_list:
                    continue
                method = getattr(resource_connections, method_name)
                for configuration in configurations_list:
                    if 'resource_id' in configuration:
                        resource_id = configuration.pop('resource_id')
                        configuration['other'] = self.get_resource(resource_id)

                    if 'port' in configuration:
                        port_configurations = configuration.pop('port')
                        for port_method_name, port_method_args in port_configurations.items():
                            if port_method_args not in (False, None):
                                port_method = getattr(ec2.Port, port_method_name)
                                if isinstance(port_method_args, dict):
                                    port = port_method(**port_method_args)
                                elif port_method_args in (True, False):
                                    port = port_method()
                                else:
                                    port = port_method(port_method_args)
                                configuration['port_range'] = port
                                break
                        else:
                            raise Exception('Invalid port configuration')

                    method(**configuration)

    def _initialize_integrations(self):
        if not self.manifest.integrations:
            return
        for integration_class_name, config in self.manifest.integrations.items():
            module_name, class_name = integration_class_name.rsplit('.', 1)
            mod = importlib.import_module(module_name)
            integration_class = getattr(mod, class_name)
            integration = integration_class(config)
            self.integrations[integration_class_name] = integration

    def _configure_integrations(self) -> None:
        for integration_class_name, integration in self.integrations.items():
            integration.configure(self, integration_class_name)
        return

    def get_resource(self, resource_id: str) -> Any:
        if '.' in resource_id:
            resource_id, *attrs = resource_id.split('.')
            attrs: list[str] = attrs[::-1]
            obj = self.resources[resource_id]
            while attrs:
                attr_name = attrs.pop()
                obj = getattr(obj, attr_name)
            return obj
        return self.resources[resource_id]

    def create_bucket(self, id: str, bucket_definition: BucketResource) -> s3.Bucket:
        return bucket_definition.to_construct(scope=self, id=id)

    def create_database(self, id: str, database_definition: RDSDatabaseResource) -> rds.DatabaseInstance:
        return database_definition.to_construct(scope=self, id=id)

    def create_application_loadbalanced_fargate_service(
        self, id: str, alb_fargate_service_definition: ApplicationLoadBalancedFargateServiceResource
    ) -> ecs_patterns.ApplicationLoadBalancedFargateService:
        return alb_fargate_service_definition.to_construct(scope=self, id=id)

    def create_fargate_service(self, id: str, fargate_service_definition: FargateServiceResource):
        return fargate_service_definition.to_construct(scope=self, id=id)

    def create_cloudfront_distribution(self, id: str, cloudfront_definition: CloudFrontDistributionResource) -> cloudfront.Distribution:
        return cloudfront_definition.to_construct(scope=self, id=id)

    def create_redis_cluster(self, id: str, redis_cluster_definition: RedisClusterResource) -> RedisCluster:
        return redis_cluster_definition.to_construct(scope=self, id=id)

    @singledispatchmethod
    def create_resource(self, id: str, definition: BaseResource) -> constructs.IConstruct | constructs.Construct:
        raise NotImplementedError()

    @create_resource.register
    def _(self, id: str, definition: BucketResource) -> s3.Bucket:
        return self.create_bucket(id, bucket_definition=definition)

    @create_resource.register
    def _(self, id: str, definition: RDSDatabaseResource) -> rds.DatabaseInstance:
        return self.create_database(id=id, database_definition=definition)

    @create_resource.register
    def _(self, id: str, definition: ApplicationLoadBalancedFargateServiceResource) -> ecs_patterns.ApplicationLoadBalancedFargateService:
        return self.create_application_loadbalanced_fargate_service(id=id, alb_fargate_service_definition=definition)

    @create_resource.register
    def _(self, id: str, definition: CloudFrontDistributionResource):
        return self.create_cloudfront_distribution(id=id, cloudfront_definition=definition)

    @create_resource.register
    def _(self, id: str, definition: RedisClusterResource) -> RedisCluster:
        return self.create_redis_cluster(id=id, redis_cluster_definition=definition)

    def _create_resources(self) -> None:
        manifest_resources = self.manifest.resources[self.environment_name]
        deferred = {}
        for resource_type, resources in manifest_resources.__dict__.items():
            for resource_id, resource_definition in resources.items():
                self.definitions[resource_id] = resource_definition
                logging.debug(f'synthesizing {resource_type} {resource_id}')
                try:
                    resource = self.create_resource(resource_id, resource_definition)
                    self.resources[resource_id] = resource
                    if isinstance(resource_definition, Connectable):
                        if resource_definition.implicit_connections_allowed is True:
                            aws_cdk.Aspects.of(resource).add(ImplicitConnectionsConfigurator(self))  # noqa
                        elif resource_definition.implicit_connections_allowed is None:
                            # defer to manifest defined behavior if the resource is not explicitly configured
                            if self.manifest.implicit_connections is True:
                                aws_cdk.Aspects.of(resource).add(ImplicitConnectionsConfigurator(self))  # noqa

                except CreationDeferredException as e:
                    logging.info(f'synthesis of resource {resource_id} ({type(resource_definition)} is being deferred. {e}')
                    deferred[resource_id] = resource_definition
                    continue
        while deferred:
            done = []
            logging.info(f'{len(deferred)} deferred resources awaiting synthesis')
            for resource_id, resource_definition in deferred.items():
                try:
                    logging.debug(f'synthesizing {resource_id}')
                    resource = self.create_resource(resource_id, resource_definition)
                    self.resources[resource_id] = resource
                    if isinstance(resource_definition, Connectable):
                        if resource_definition.implicit_connections_allowed is True:
                            aws_cdk.Aspects.of(resource).add(ImplicitConnectionsConfigurator(self))  # noqa
                        elif resource_definition.implicit_connections_allowed is None:
                            # defer to manifest defined behavior if the resource is not explicitly configured
                            if self.manifest.implicit_connections is True:
                                aws_cdk.Aspects.of(resource).add(ImplicitConnectionsConfigurator(self))  # noqa
                    done.append(resource_id)
                except CreationDeferredException as e:
                    logging.info(f'Synthesis of resource {resource_id} ({type(resource_definition)} is being deferred (again). {e}')
            for d in done:
                del deferred[d]
            if not done and deferred:
                # No progress could be made on deferred resources
                # this could be a programming error or some kind of cyclical reference.
                raise RuntimeError(
                    f'Failure in resolving deferred resources. Possible cyclical reference has occurred. {len(deferred)} resources remaining.',
                    deferred,
                )
            done = []

    @classmethod
    def from_manifest_file(
        cls, scope: aws_cdk.App, file_path: str, provider: EnvironmentProvider, loader: Optional[ManifestLoader] = None, **kwargs
    ):
        if loader is None:
            loader = ManifestLoader()
        manifest = loader.load(
            file_path=file_path, environment_name=provider.environment_name, account=provider.account, region=provider.region
        )
        kwargs['manifest'] = manifest
        return cls(scope, provider, **kwargs)

    @classmethod
    def with_dynamic_provider(
        cls,
        scope: aws_cdk.App,
        file_path: str,
        loader: Optional[ManifestLoader] = None,
        provider_kwargs: Optional[dict[str, Any]] = None,
        **kwargs,
    ):
        if provider_kwargs is None:
            provider_kwargs = {}
        if loader is None:
            loader = ManifestLoader()
        initial_manifest = loader.load(
            file_path=file_path,
            environment_name=provider_kwargs.get('environment_name', ''),
            account=provider_kwargs.get('account', ''),
            region=provider_kwargs.get('region', ''),
        )
        ProviderClass = initial_manifest.get_provider_class()
        provider = ProviderClass(**provider_kwargs)
        manifest = loader.load(
            file_path=file_path, environment_name=provider.environment_name, account=provider.account, region=provider.region
        )
        kwargs['manifest'] = manifest
        return cls(scope, provider, **kwargs)


def _deep_merge(d1: dict[str, Any], d2: dict[str, Any]) -> dict[str, Any]:
    new_dict = {}
    for key, val in d1.items():
        if key not in d2:
            new_dict[key] = val
            continue
        other_val = d2[key]
        if isinstance(val, dict) and isinstance(other_val, dict):
            new_val = _deep_merge(val, other_val)
            new_dict[key] = new_val
        else:
            new_dict[key] = other_val
    return new_dict


class ManifestLoader:
    def __init__(self, **kwargs):
        self._kwargs = kwargs

    def _make_context(self, **kwargs) -> dict[str, Any]:
        return dict(**kwargs)

    def load(self, file_path, environment_name, account: str, region: str, **template_kwargs) -> Manifest:
        with open(file_path, 'r') as f:
            data = f.read()
        jinja_env = self.get_jinja_environment()
        template = jinja_env.from_string(data)
        context = self._make_context(environment_name=environment_name, account=account, region=region, **template_kwargs)
        rendered_data = template.render(context)
        manifest_data = yaml.load(rendered_data, Loader=yaml.SafeLoader)
        resources = manifest_data.pop('resources')
        default_resources = resources.pop('default', {})
        environment_resources = resources.pop(environment_name, {})
        environment_merged_resources = _deep_merge(default_resources, environment_resources)
        manifest_data['resources'] = {environment_name: environment_merged_resources}
        manifest = Manifest.parse_obj(manifest_data)
        return manifest

    def get_jinja_environment(self) -> jinja2.Environment:
        env = jinja2.Environment(loader=jinja2.BaseLoader())
        return env


def _manifest_schema(indent: int = 4, outfile: Optional[str] = None) -> str:
    schema = Manifest.schema_json(indent=indent)
    if outfile:
        with open(outfile, 'w') as f:
            f.write(schema)
    else:
        print(schema)
    return schema


_integration_registry = {}


class IntegrationBase:
    def __init_subclass__(cls, **kwargs):
        if hasattr(cls, 'integration_name'):
            name = cls.integration_name
        else:
            name = '.'.join([cls.__module__, cls.__qualname__])
        if name in _integration_registry:
            raise Exception(f'Integration with name {name} already registered')
        _integration_registry[name] = cls
        return super().__init_subclass__(**kwargs)

    def __init__(self, configuration: dict[str, Any]):
        self.configuration: dict[str, Any] = configuration

    @abc.abstractmethod
    def configure(self, manifest_stack: ManifestStack, id: str) -> constructs.Construct | constructs.IConstruct:
        ...


# TODO: move concrete integrations into separate package (in part, so they can be versioned separately)


class GitHubActionsIntegrationConfiguration(pydantic.BaseModel):
    repositories: list[str] = ...
    role_name: Optional[str] = None
    oidc_provider_arn: str = ...


class GitLabCICDIntegrationConfiguration(pydantic.BaseModel):
    project_paths: list[str] = ...
    oidc_provider_arn: str = ...
    role_name: Optional[str] = None


class DeployConstruct(constructs.Construct):
    def __init__(
        self,
        scope: ManifestStack,
        id: str,
        *,
        configuration: GitHubActionsIntegrationConfiguration | GitLabCICDIntegrationConfiguration,
    ):
        super().__init__(scope, id)
        self.manifest_stack = scope
        self.configuration = configuration

    def _make_role(self, assumed_by, role_name: Optional[str] = None):
        if role_name is None:
            role_name = f'level4-deploy-{self.manifest_stack.stack_name}'
        self.deployment_role = iam.Role(self, 'deploy-role', role_name=role_name, assumed_by=assumed_by)
        aws_cdk.CfnOutput(self, 'deployrole', value=self.deployment_role.role_arn)

    def _configure_resources(self):
        self._configured_ecs_baselines = False
        for resource_id, definition in self.manifest_stack.definitions.items():
            self.configure_deployment(resource_id, definition)
        if self._configured_ecs_baselines:
            self.deployment_role.add_to_policy(self.ecs_service_deploy_policy)

    @singledispatchmethod
    def configure_deployment(self, definition: BaseResource, id: str) -> None:
        return None

    @configure_deployment.register
    def _(self, definition: BucketResource, id: str) -> None:
        resource: s3.Bucket = self.manifest_stack.resources[id]  # type: ignore
        resource.grant_read_write(self.deployment_role)

    @configure_deployment.register
    def _(self, definition: RDSDatabaseResource, id: str) -> None:
        resource: rds.DatabaseInstance = self.manifest_stack.resources[id]  # type: ignore
        resource.secret.grant_read(self.deployment_role)

    @configure_deployment.register
    def _(self, definition: ApplicationLoadBalancedFargateServiceResource, id: str) -> None:
        resource: ecs_patterns.ApplicationLoadBalancedFargateService = self.manifest_stack.resources[id]  # type: ignore
        for container_name, container_definition in definition.containers.items():
            repo = ecr.Repository.from_repository_name(self, f'{container_name}-repo', repository_name=container_definition.ecr_repository)
            repo.grant_pull_push(self.deployment_role)
        if not self._configured_ecs_baselines:
            self._configured_ecs_baselines = True
            self.deployment_role.add_to_policy(
                iam.PolicyStatement(
                    actions=['ecs:DescribeTaskDefinition', 'ecs:RegisterTaskDefinition'],
                    resources=['*'],
                    effect=iam.Effect.ALLOW,
                )
            )
            self.ecs_service_deploy_policy = iam.PolicyStatement(
                actions=['ecs:UpdateService', 'ecs:DescribeServices'], effect=iam.Effect.ALLOW
            )
        self.ecs_service_deploy_policy.add_resources(resource.service.service_arn)
        exec_role = resource.task_definition.execution_role or resource.task_definition.obtain_execution_role()
        if exec_role:
            exec_role.grant_pass_role(self.deployment_role)
        task_role = resource.task_definition.task_role
        if task_role:
            task_role.grant_pass_role(self.deployment_role)

    @configure_deployment.register
    def _(self, definition: CloudFrontDistributionResource, id: str) -> None:
        resource: cloudfront.Distribution = self.manifest_stack.resources[id]  # type: ignore
        print(resource, type(definition), file=sys.stderr)
        self.deployment_role.add_to_policy(
            iam.PolicyStatement(
                actions=['cloudfront:GetDistribution', 'cloudfront:CreateInvalidation'],
                effect=iam.Effect.ALLOW,
                resources=['arn:aws:cloudfront::*:distribution/' + resource.distribution_id],
            )
        )


class GitHubActionIntegrationConstruct(DeployConstruct):
    def __init__(self, scope: ManifestStack, id: str, *, configuration: GitHubActionsIntegrationConfiguration):
        super().__init__(scope, id, configuration=configuration)
        conditions = {'StringEquals': {'token.actions.githubusercontent.com:aud': 'sts.amazonaws.com'}}
        condition = {'StringLike': {'token.actions.githubusercontent.com:sub': []}}

        for repo in configuration.repositories:
            condition['StringLike']['token.actions.githubusercontent.com:sub'].append(f'repo:{repo}:*')

        conditions.update(**condition)
        principal = iam.FederatedPrincipal(
            configuration.oidc_provider_arn, assume_role_action='sts:AssumeRoleWithWebIdentity'
        ).with_conditions(conditions)
        self._make_role(role_name=configuration.role_name, assumed_by=principal)
        self._configure_resources()


class GitLabCICDIntegrationConstruct(DeployConstruct):
    def __init__(self, scope: ManifestStack, id: str, *, configuration: GitLabCICDIntegrationConfiguration):
        super().__init__(scope, id, configuration=configuration)
        condition = {'gitlab.example.com:sub': []}
        provider_url = configuration.oidc_provider_arn.split('/')[-1]
        for repo in configuration.project_paths:
            condition[f'{provider_url}:sub'].append(f'repo:{repo}:*')

        principal = iam.FederatedPrincipal(
            configuration.oidc_provider_arn, assume_role_action='sts:AssumeRoleWithWebIdentity'
        ).with_conditions(conditions={'StringLike': condition})
        self._make_role(role_name=configuration.role_name, assumed_by=principal)
        self._configure_resources()


class GitHubActionsIntegration(IntegrationBase):
    def __init__(self, configuration: dict[str, Any]):
        super().__init__(configuration=configuration)
        self.definition = GitHubActionsIntegrationConfiguration(**self.configuration)

    def configure(self, manifest_stack: ManifestStack, id: str) -> GitHubActionIntegrationConstruct:
        return GitHubActionIntegrationConstruct(scope=manifest_stack, id=id, configuration=self.definition)


class GitLabActionsIntegration(IntegrationBase):
    def __init__(self, configuration: dict[str, Any]):
        super().__init__(configuration=configuration)
        self.definition = GitLabCICDIntegrationConfiguration(**self.configuration)

    def configure(self, manifest_stack: ManifestStack, id: str) -> GitLabCICDIntegrationConstruct:
        return GitLabCICDIntegrationConstruct(scope=manifest_stack, id=id, configuration=self.definition)


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(help='sub-command help', dest='command')
    schema_parser = subparsers.add_parser('schema', help='schema help')
    schema_parser.add_argument('--indent', type=int, default=4, help='Indentation of the schema.json file')
    schema_parser.add_argument('-o', help='outfile path to write schema', dest='outfile')
    args = parser.parse_args()
    if args.command == 'schema':
        _manifest_schema(indent=args.indent, outfile=args.outfile)
