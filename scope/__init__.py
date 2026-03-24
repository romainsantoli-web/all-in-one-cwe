"""Scope management for targeted/restricted scanning."""

from scope.parser import ScopeParser, ScopeConfig
from scope.enforcer import ScopeEnforcer

__all__ = ["ScopeConfig", "ScopeEnforcer", "ScopeParser"]
