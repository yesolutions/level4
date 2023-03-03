import pkg_resources

from .model import EnvironmentProvider
from .model import ManifestLoader
from .model import ManifestStack

__VERSION__ = pkg_resources.get_distribution('level4').version

__all__ = ['EnvironmentProvider', 'ManifestStack', 'ManifestLoader']
