"""
Compatibility shim for pkg_resources.
Setuptools >= 82.0.0 completely removed pkg_resources, but legacy packages
such as Flask-RQ2 still import get_distribution and DistributionNotFound from it.
This shim maps those calls to importlib.metadata to prevent ModuleNotFoundError.
"""
from importlib import metadata
import sys


class DistributionNotFound(Exception):
    pass


class RequirementParseError(Exception):
    pass


class _Distribution:
    def __init__(self, name: str):
        self.project_name = name
        try:
            self.version = metadata.version(name)
        except (metadata.PackageNotFoundError, ValueError):
            raise DistributionNotFound(f"Package '{name}' not found")

    def __str__(self):
        return f"{self.project_name} {self.version}"


def get_distribution(name: str):
    return _Distribution(name)


def iter_entry_points(group, name=None):
    eps = metadata.entry_points()
    if hasattr(eps, "select"):
        matches = list(eps.select(group=group))
    else:
        matches = list(eps.get(group, []))
    if name is not None:
        matches = [ep for ep in matches if getattr(ep, "name", None) == name]
    return matches


__all__ = ["DistributionNotFound", "RequirementParseError", "get_distribution", "iter_entry_points"]

# Ensure self is registered in sys.modules
sys.modules.setdefault("pkg_resources", sys.modules[__name__])
