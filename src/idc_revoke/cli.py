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


def load_config(path: str | Path) -> dict[str, Any]:
    with open(path, "rb") as handle:
        return tomllib.load(handle)


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
    if kind == "inline_policy":
        return InlinePolicyStore(
            session.client("sso-admin"),
            config["instance_arn"],
            entry["permission_set_arn"],
            entry.get("provision", True),
        )
    raise ValueError(f"unknown deny list type: {kind}")


def build_revoker(
    config: dict[str, Any],
    dry_run: bool,
    session_factory: Callable[..., Any] = boto3.Session,
) -> Revoker:
    """Turn a configuration (see README) into a ready ``Revoker``."""
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
    home = sessions.get()
    return Revoker(
        identitystore=home.client("identitystore"),
        identity_store_id=config["identity_store_id"],
        deny_lists=deny_lists,
        sso_admin=home.client("sso-admin"),
        instance_arn=config.get("instance_arn"),
        remove_assignments=config.get("remove_assignments", False),
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
    return 0


EXPECTED_ERRORS = (OSError, ValueError, LookupError, BotoCoreError, ClientError)


def _explain(error: Exception) -> str:
    """One line a person can act on, in place of a traceback."""
    if isinstance(error, tomllib.TOMLDecodeError):
        return f"the config file is not valid TOML: {error}"
    if isinstance(error, OSError):
        return f"cannot read the config file: {error}"
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
