from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from idc_revoke.core import DenyList, Revoker, User, UserNotFoundError
from idc_revoke.policy import list_values

SID = "DenyRevoked"
NOW = datetime(2026, 11, 18, 15, 0, tzinfo=UTC)


class MemoryStore:
    def __init__(self, name, key, values):
        self.name = name
        self.writes = 0
        self.document = {
            "Statement": [
                {"Sid": SID, "Condition": {"StringEquals": {key: list(values)}}}
            ]
        }

    def read(self):
        return self.document

    def write(self, document):
        self.writes += 1
        self.document = document


def make_identitystore(found=True):
    client = MagicMock()
    if found:
        client.get_user_id.return_value = {"UserId": "u-1"}
    else:
        client.get_user_id.side_effect = ClientError(
            {"Error": {"Code": "ResourceNotFoundException", "Message": "no"}},
            "GetUserId",
        )
    client.list_group_memberships_for_member.side_effect = [
        {"GroupMemberships": [{"GroupId": "g-1"}], "NextToken": "t"},
        {"GroupMemberships": [{"GroupId": "g-2"}]},
    ]
    client.describe_group.side_effect = lambda **kw: {
        "DisplayName": f"name-{kw['GroupId']}"
    }
    return client


def make_sso_admin():
    client = MagicMock()
    client.list_account_assignments_for_principal.side_effect = [
        {
            "AccountAssignments": [{"AccountId": "111", "PermissionSetArn": "ps-a"}],
            "NextToken": "t",
        },
        {"AccountAssignments": [{"AccountId": "222", "PermissionSetArn": "ps-b"}]},
    ]
    return client


def make_revoker(**kwargs):
    ids = MemoryStore("ids", "identitystore:UserId", ["PLACEHOLDER"])
    names = MemoryStore("names", "aws:userid", ["PLACEHOLDER"])
    deny_lists = [
        DenyList(ids, SID),
        DenyList(names, SID, key="aws:userid", template="*:{user_name}"),
    ]
    defaults = {
        "identitystore": make_identitystore(),
        "identity_store_id": "d-1",
        "deny_lists": deny_lists,
        "clock": lambda: NOW,
    }
    defaults.update(kwargs)
    return Revoker(**defaults), ids, names


def values(store, key):
    return list_values(store.document, SID, "StringEquals", key)


def test_deny_list_value_uses_the_template():
    user = User("u-1", "jane")
    assert DenyList(None, SID).value_for(user) == "u-1"
    assert DenyList(None, SID, template="*:{user_name}").value_for(user) == "*:jane"


def test_find_user_looks_up_by_user_name():
    revoker, _, _ = make_revoker()
    assert revoker.find_user("jane") == User("u-1", "jane")
    revoker.identitystore.get_user_id.assert_called_once_with(
        IdentityStoreId="d-1",
        AlternateIdentifier={
            "UniqueAttribute": {"AttributePath": "userName", "AttributeValue": "jane"}
        },
    )


def test_find_user_raises_when_the_user_does_not_exist():
    revoker, _, _ = make_revoker(identitystore=make_identitystore(found=False))
    with pytest.raises(UserNotFoundError):
        revoker.find_user("ghost")


def test_find_user_lets_other_errors_through():
    client = make_identitystore()
    client.get_user_id.side_effect = ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "no"}}, "GetUserId"
    )
    revoker, _, _ = make_revoker(identitystore=client)
    with pytest.raises(ClientError):
        revoker.find_user("jane")


def test_revoke_adds_the_user_to_every_deny_list():
    revoker, ids, names = make_revoker()
    report = revoker.revoke("jane")
    assert values(ids, "identitystore:UserId") == ["PLACEHOLDER", "u-1"]
    assert values(names, "aws:userid") == ["PLACEHOLDER", "*:jane"]
    assert report.action == "revoke"
    assert report.user == User("u-1", "jane")
    assert report.changed == ["ids/DenyRevoked", "names/DenyRevoked"]
    assert report.unchanged == []
    assert report.groups == ["name-g-1", "name-g-2"]
    assert report.restore_after == NOW + timedelta(hours=12)
    assert report.manual_steps
    assert report.removed_assignments == []


def test_revoke_twice_writes_nothing_the_second_time():
    revoker, ids, _ = make_revoker()
    revoker.revoke("jane")
    revoker.identitystore.list_group_memberships_for_member.side_effect = [
        {"GroupMemberships": []}
    ]
    report = revoker.revoke("jane")
    assert ids.writes == 1
    assert report.changed == []
    assert report.unchanged == ["ids/DenyRevoked", "names/DenyRevoked"]


def test_dry_run_reports_but_changes_nothing():
    sso_admin = make_sso_admin()
    revoker, ids, _ = make_revoker(
        dry_run=True, sso_admin=sso_admin, instance_arn="ins", remove_assignments=True
    )
    report = revoker.revoke("jane")
    assert report.dry_run is True
    assert report.changed == ["ids/DenyRevoked", "names/DenyRevoked"]
    assert report.removed_assignments == ["111/ps-a", "222/ps-b"]
    assert ids.writes == 0
    sso_admin.delete_account_assignment.assert_not_called()


def test_revoke_removes_direct_assignments_when_asked():
    sso_admin = make_sso_admin()
    revoker, _, _ = make_revoker(
        sso_admin=sso_admin, instance_arn="ins", remove_assignments=True
    )
    report = revoker.revoke("jane")
    assert report.removed_assignments == ["111/ps-a", "222/ps-b"]
    assert sso_admin.delete_account_assignment.call_count == 2
    sso_admin.delete_account_assignment.assert_any_call(
        InstanceArn="ins",
        TargetId="222",
        TargetType="AWS_ACCOUNT",
        PermissionSetArn="ps-b",
        PrincipalType="USER",
        PrincipalId="u-1",
    )


def test_restore_removes_the_user_and_has_no_follow_up():
    revoker, ids, names = make_revoker()
    revoker.revoke("jane")
    report = revoker.restore("jane")
    assert values(ids, "identitystore:UserId") == ["PLACEHOLDER"]
    assert values(names, "aws:userid") == ["PLACEHOLDER"]
    assert report.action == "restore"
    assert report.restore_after is None
    assert report.manual_steps == []
    assert report.groups == []


def test_restore_works_for_a_deleted_user_when_the_id_is_given():
    revoker, ids, _ = make_revoker(identitystore=make_identitystore(found=False))
    ids.document["Statement"][0]["Condition"]["StringEquals"][
        "identitystore:UserId"
    ].append("u-9")
    report = revoker.restore("jane", user_id="u-9")
    assert report.user == User("u-9", "jane")
    assert values(ids, "identitystore:UserId") == ["PLACEHOLDER"]


def test_status_says_which_deny_lists_hold_the_user():
    revoker, ids, _ = make_revoker()
    ids.document = revoker.deny_lists[0].with_user(ids.document, User("u-1", "jane"))
    assert revoker.status("jane") == {
        "ids/DenyRevoked": True,
        "names/DenyRevoked": False,
    }


def test_report_converts_to_plain_data():
    revoker, _, _ = make_revoker()
    data = revoker.revoke("jane").to_dict()
    assert data["user"] == {"user_id": "u-1", "user_name": "jane"}
    assert data["restore_after"] == "2026-11-19T03:00:00+00:00"
    revoker.identitystore.list_group_memberships_for_member.side_effect = None
    assert revoker.restore("jane").to_dict()["restore_after"] is None
