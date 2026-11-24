"""Command line: ``idc-revoke --config revoke.toml revoke <user name>``."""

import argparse
import json
import sys
import tomllib
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from idc_revoke.core import DenyList, Revoker, UserNotFoundError
from idc_revoke.stores import (
    DenyListStore,
    InlinePolicyStore,
    ManagedPolicyStore,
    ScpStore,
)


class ConfigError(ValueError):
    """The config file cannot be read or holds a mistake."""


TOP_LEVEL = {
    "identity_store_id",
    "instance_arn",
    "region",
    "profile",
    "remove_assignments",
    "retention_hours",
    "deny_list",
}
ENTRY_COMMON = {"type", "sid", "key", "operator", "template", "profile", "role_arn"}
ENTRY_OWN = {
    "scp": {"policy_id"},
    "managed_policy": {"policy_arn"},
    "inline_policy": {"permission_set_arn", "provision"},
}
ENTRY_NEEDS = {
    "scp": "policy_id",
    "managed_policy": "policy_arn",
    "inline_policy": "permission_set_arn",
}


def load_config(path: str | Path) -> dict[str, Any]:
    try:
        with open(path, "rb") as handle:
            return tomllib.load(handle)
    except OSError as error:
        raise ConfigError(f"cannot read the config file: {error}") from error
    except tomllib.TOMLDecodeError as error:
        raise ConfigError(f"the config file is not valid TOML: {error}") from error


def validate_config(config: dict[str, Any]) -> None:
    """Refuse a config with a typo: a setting ignored in silence is a risk."""
    for key in config:
        if key not in TOP_LEVEL:
            raise ConfigError(f"unknown setting: {key}")
    if not config.get("identity_store_id"):
        raise ConfigError("missing setting: identity_store_id")
    if not isinstance(config.get("remove_assignments", True), bool):
        raise ConfigError("remove_assignments must be true or false")
    hours = config.get("retention_hours", 12)
    if isinstance(hours, bool) or not isinstance(hours, int | float):
        raise ConfigError("retention_hours must be a number")
    entries = config.get("deny_list")
    if not isinstance(entries, list) or not entries:
        raise ConfigError("the config needs at least one [[deny_list]]")
    for number, entry in enumerate(entries, start=1):
        if not isinstance(entry, dict):
            raise ConfigError(f"deny_list {number} must be a table")
        kind = entry.get("type")
        if kind not in ENTRY_OWN:
            raise ConfigError(f"unknown deny list type: {kind}")
        for key in entry:
            if key not in ENTRY_COMMON | ENTRY_OWN[kind]:
                raise ConfigError(f"unknown setting in deny_list {number}: {key}")
        for needed in ("sid", ENTRY_NEEDS[kind]):
            if not entry.get(needed):
                raise ConfigError(f"deny_list {number} ({kind}) needs {needed}")


class _Sessions:
    """One boto3 session per profile or assumed role, created on demand."""

    def __init__(self, config: dict[str, Any], factory: Callable[..., Any]) -> None:
        self.factory = factory
        self.region = config.get("region")
        self.default_profile = config.get("profile")
        self.cache: dict[tuple[str | None, str | None], Any] = {}

    def _new(self, **kwargs: Any) -> Any:
        if self.region:
            kwargs["region_name"] = self.region
        return self.factory(**kwargs)

    def get(self, profile: str | None = None, role_arn: str | None = None) -> Any:
        key = (profile or self.default_profile, role_arn)
        if key not in self.cache:
            if role_arn:
                sts = self.get(profile).client("sts")
                credentials = sts.assume_role(
                    RoleArn=role_arn, RoleSessionName="idc-revoke"
                )["Credentials"]
                self.cache[key] = self._new(
                    aws_access_key_id=credentials["AccessKeyId"],
                    aws_secret_access_key=credentials["SecretAccessKey"],
                    aws_session_token=credentials["SessionToken"],
                )
            elif key[0]:
                self.cache[key] = self._new(profile_name=key[0])
            else:
                self.cache[key] = self._new()
        return self.cache[key]


def _store(
    entry: dict[str, Any], config: dict[str, Any], sessions: _Sessions
) -> DenyListStore:
    session = sessions.get(entry.get("profile"), entry.get("role_arn"))
    kind = entry["type"]
    if kind == "scp":
        return ScpStore(session.client("organizations"), entry["policy_id"])
    if kind == "managed_policy":
        return ManagedPolicyStore(session.client("iam"), entry["policy_arn"])
    return InlinePolicyStore(
        session.client("sso-admin"),
        config["instance_arn"],
        entry["permission_set_arn"],
        entry.get("provision", True),
    )


def build_revoker(
    config: dict[str, Any],
    dry_run: bool,
    session_factory: Callable[..., Any] = boto3.Session,
) -> Revoker:
    """Turn a configuration (see README) into a ready ``Revoker``."""
    validate_config(config)
    sessions = _Sessions(config, session_factory)
    deny_lists = [
        DenyList(
            _store(entry, config, sessions),
            entry["sid"],
            entry.get("key", "identitystore:UserId"),
            entry.get("operator", "StringEquals"),
            entry.get("template", "{user_id}"),
        )
        for entry in config["deny_list"]
    ]
    remove_assignments = config.get("remove_assignments", True)
    if remove_assignments and not config.get("instance_arn"):
        raise ValueError(
            "instance_arn is needed to remove account assignments "
            "(or set remove_assignments = false)"
        )
    home = sessions.get()
    return Revoker(
        identitystore=home.client("identitystore"),
        identity_store_id=config["identity_store_id"],
        deny_lists=deny_lists,
        sso_admin=home.client("sso-admin"),
        instance_arn=config.get("instance_arn"),
        remove_assignments=remove_assignments,
        retention=timedelta(hours=config.get("retention_hours", 12)),
        dry_run=dry_run,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="idc-revoke", description=__doc__)
    parser.add_argument("--config", required=True, help="path to the TOML file")
    parser.add_argument("--dry-run", action="store_true", help="change nothing")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("revoke", "restore", "status"):
        command = commands.add_parser(name)
        command.add_argument("user_name")
        if name == "restore":
            command.add_argument("--user-id", help="needed if the user was deleted")
    args = parser.parse_args(argv)
    try:
        result = _run(args)
    except EXPECTED_ERRORS as error:
        print(f"idc-revoke: {_explain(error)}", file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    failed = result.get("failed") or []
    if failed:
        steps = "1 step" if len(failed) == 1 else f"{len(failed)} steps"
        print(f'idc-revoke: {steps} failed, see "failed" above', file=sys.stderr)
        return 1
    return 0


EXPECTED_ERRORS = (OSError, ValueError, LookupError, BotoCoreError, ClientError)


def _explain(error: Exception) -> str:
    """One line a person can act on, in place of a traceback."""
    if isinstance(error, UserNotFoundError):
        return f"no Identity Center user named {error}"
    if isinstance(error, KeyError):
        return f"missing setting: {error.args[0]}"
    if isinstance(error, BotoCoreError | ClientError):
        return f"AWS error: {error}"
    return str(error)


def _run(args: argparse.Namespace) -> Any:
    revoker = build_revoker(load_config(args.config), args.dry_run)
    if args.command == "revoke":
        return revoker.revoke(args.user_name).to_dict()
    if args.command == "restore":
        return revoker.restore(args.user_name, args.user_id).to_dict()
    return revoker.status(args.user_name)
