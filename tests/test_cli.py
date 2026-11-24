import json
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError, NoCredentialsError

from idc_revoke import cli
from idc_revoke.core import DenyList, RevokeReport, User, UserNotFoundError
from idc_revoke.policy import StatementNotFoundError
from idc_revoke.stores import InlinePolicyStore, ManagedPolicyStore, ScpStore

CONFIG = """
identity_store_id = "d-1"
instance_arn = "ins"
region = "ca-central-1"
profile = "mgmt"
remove_assignments = true
retention_hours = 4

[[deny_list]]
type = "scp"
policy_id = "p-1"
sid = "DenyIds"

[[deny_list]]
type = "managed_policy"
policy_arn = "arn:aws:iam::111:policy/DenyList"
profile = "member"
sid = "DenyNames"
key = "aws:userid"
operator = "StringLike"
template = "*:{user_name}"

[[deny_list]]
type = "managed_policy"
policy_arn = "arn:aws:iam::222:policy/DenyList"
role_arn = "arn:aws:iam::222:role/Admin"
sid = "DenyIds"

[[deny_list]]
type = "inline_policy"
permission_set_arn = "ps-1"
provision = false
sid = "DenyIds"
"""


@pytest.fixture
def config_file(tmp_path):
    path = tmp_path / "revoke.toml"
    path.write_text(CONFIG)
    return path


@pytest.fixture
def sessions():
    created = []

    def factory(**kwargs):
        session = MagicMock(name=f"session{len(created)}")
        session.kwargs = kwargs
        session.client.return_value.assume_role.return_value = {
            "Credentials": {
                "AccessKeyId": "AK",
                "SecretAccessKey": "SK",
                "SessionToken": "ST",
            }
        }
        created.append(session)
        return session

    factory.created = created
    return factory


def test_build_revoker_reads_the_whole_configuration(config_file, sessions):
    revoker = cli.build_revoker(cli.load_config(config_file), False, sessions)
    assert revoker.identity_store_id == "d-1"
    assert revoker.instance_arn == "ins"
    assert revoker.remove_assignments is True
    assert revoker.retention.total_seconds() == 4 * 3600
    assert revoker.dry_run is False
    scp, by_profile, by_role, inline = revoker.deny_lists
    assert isinstance(scp.store, ScpStore)
    assert (scp.sid, scp.key, scp.template) == (
        "DenyIds",
        "identitystore:UserId",
        "{user_id}",
    )
    assert isinstance(by_profile.store, ManagedPolicyStore)
    assert (by_profile.operator, by_profile.template) == (
        "StringLike",
        "*:{user_name}",
    )
    assert isinstance(by_role.store, ManagedPolicyStore)
    assert isinstance(inline.store, InlinePolicyStore)
    assert inline.store.provision is False
    assert {"profile_name": "mgmt", "region_name": "ca-central-1"} in [
        s.kwargs for s in sessions.created
    ]
    assert {"profile_name": "member", "region_name": "ca-central-1"} in [
        s.kwargs for s in sessions.created
    ]
    assert {
        "aws_access_key_id": "AK",
        "aws_secret_access_key": "SK",
        "aws_session_token": "ST",
        "region_name": "ca-central-1",
    } in [s.kwargs for s in sessions.created]


def test_sessions_are_reused_for_the_same_profile(config_file, sessions):
    cli.build_revoker(cli.load_config(config_file), False, sessions)
    profiles = [s.kwargs.get("profile_name") for s in sessions.created]
    assert profiles.count("mgmt") == 1


def test_unknown_deny_list_type_is_rejected(sessions):
    config = {"identity_store_id": "d-1", "deny_list": [{"type": "x", "sid": "s"}]}
    with pytest.raises(ValueError, match="unknown deny list type"):
        cli.build_revoker(config, False, sessions)


def test_minimal_configuration_uses_defaults(sessions):
    config = {
        "identity_store_id": "d-1",
        "deny_list": [{"type": "scp", "policy_id": "p-1", "sid": "s"}],
    }
    revoker = cli.build_revoker(config, True, sessions)
    assert revoker.dry_run is True
    assert revoker.remove_assignments is False
    assert revoker.retention.total_seconds() == 12 * 3600
    assert sessions.created[0].kwargs == {}


@pytest.mark.parametrize(
    ("argv", "method", "expected"),
    [
        (["revoke", "jane"], "revoke", ("jane",)),
        (["restore", "jane", "--user-id", "u-1"], "restore", ("jane", "u-1")),
        (["restore", "jane"], "restore", ("jane", None)),
    ],
)
def test_main_runs_the_command_and_prints_the_report(
    config_file, monkeypatch, capsys, argv, method, expected
):
    revoker = MagicMock()
    report = RevokeReport(User("u-1", "jane"), method, True)
    getattr(revoker, method).return_value = report
    seen = {}

    def fake_build(config, dry_run, session_factory=None):
        seen["dry_run"] = dry_run
        return revoker

    monkeypatch.setattr(cli, "build_revoker", fake_build)
    code = cli.main(["--config", str(config_file), "--dry-run", *argv])
    assert code == 0
    assert seen["dry_run"] is True
    getattr(revoker, method).assert_called_once_with(*expected)
    assert json.loads(capsys.readouterr().out)["action"] == method


def test_main_status_prints_the_deny_lists(config_file, monkeypatch, capsys):
    revoker = MagicMock()
    revoker.status.return_value = {"scp:p-1/DenyIds": True}
    monkeypatch.setattr(cli, "build_revoker", lambda *a, **k: revoker)
    assert cli.main(["--config", str(config_file), "status", "jane"]) == 0
    assert json.loads(capsys.readouterr().out) == {"scp:p-1/DenyIds": True}


def test_deny_list_is_exported_for_module_users():
    import idc_revoke

    assert idc_revoke.DenyList is DenyList
    assert idc_revoke.ScpStore is ScpStore


def test_missing_config_file_is_a_clean_error(tmp_path, capsys):
    code = cli.main(["--config", str(tmp_path / "nope.toml"), "status", "jane"])
    assert code == 1
    error = capsys.readouterr().err
    assert error.startswith("idc-revoke: cannot read the config file")
    assert "Traceback" not in error


def test_invalid_config_file_is_a_clean_error(tmp_path, capsys):
    path = tmp_path / "revoke.toml"
    path.write_text("deny_list = [")
    assert cli.main(["--config", str(path), "status", "jane"]) == 1
    assert capsys.readouterr().err.startswith(
        "idc-revoke: the config file is not valid TOML"
    )


@pytest.mark.parametrize(
    ("raised", "message"),
    [
        (KeyError("identity_store_id"), "missing setting: identity_store_id"),
        (UserNotFoundError("jane"), "no Identity Center user named jane"),
        (StatementNotFoundError("no statement 'x'"), "no statement 'x'"),
        (ValueError("unknown deny list type: x"), "unknown deny list type: x"),
        (
            ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "Op"),
            "AWS error: An error occurred (AccessDenied)",
        ),
        (NoCredentialsError(), "AWS error: Unable to locate credentials"),
    ],
)
def test_expected_failures_are_clean_errors(
    config_file, monkeypatch, capsys, raised, message
):
    def fail(*args, **kwargs):
        raise raised

    monkeypatch.setattr(cli, "build_revoker", fail)
    assert cli.main(["--config", str(config_file), "revoke", "jane"]) == 1
    captured = capsys.readouterr()
    assert captured.err.startswith(f"idc-revoke: {message}")
    assert captured.out == ""
