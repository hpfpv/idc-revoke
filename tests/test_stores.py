import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

from idc_revoke.stores import InlinePolicyStore, ManagedPolicyStore, ScpStore

DOC = {"Version": "2012-10-17", "Statement": []}
ARN = "arn:aws:iam::111111111111:policy/DenyList"


def test_scp_store_reads_and_writes_the_policy_content():
    client = MagicMock()
    client.describe_policy.return_value = {"Policy": {"Content": json.dumps(DOC)}}
    store = ScpStore(client, "p-123")
    assert store.name == "scp:p-123"
    assert store.read() == DOC
    store.write(DOC)
    client.update_policy.assert_called_once_with(
        PolicyId="p-123", Content=json.dumps(DOC)
    )


def make_iam(versions, document=DOC):
    client = MagicMock()
    client.get_policy.return_value = {"Policy": {"DefaultVersionId": "v2"}}
    client.get_policy_version.return_value = {"PolicyVersion": {"Document": document}}
    client.list_policy_versions.return_value = {"Versions": versions}
    return client


def version(version_id, day, default=False):
    return {
        "VersionId": version_id,
        "IsDefaultVersion": default,
        "CreateDate": datetime(2026, 1, day, tzinfo=UTC),
    }


def test_managed_policy_store_reads_the_default_version():
    client = make_iam([])
    store = ManagedPolicyStore(client, ARN)
    assert store.name == f"managed-policy:{ARN}"
    assert store.read() == DOC
    client.get_policy_version.assert_called_once_with(PolicyArn=ARN, VersionId="v2")


def test_managed_policy_store_accepts_a_json_string_document():
    assert ManagedPolicyStore(make_iam([], json.dumps(DOC)), ARN).read() == DOC


def test_managed_policy_store_writes_a_new_default_version():
    client = make_iam([version("v1", 1), version("v2", 2, default=True)])
    ManagedPolicyStore(client, ARN).write(DOC)
    client.delete_policy_version.assert_not_called()
    client.create_policy_version.assert_called_once_with(
        PolicyArn=ARN, PolicyDocument=json.dumps(DOC), SetAsDefault=True
    )


def test_managed_policy_store_prunes_the_oldest_non_default_version_when_full():
    versions = [
        version("v5", 5, default=True),
        version("v3", 3),
        version("v2", 2),
        version("v4", 4),
        version("v1", 1, default=False),
    ]
    client = make_iam(versions)
    ManagedPolicyStore(client, ARN).write(DOC)
    client.delete_policy_version.assert_called_once_with(PolicyArn=ARN, VersionId="v1")


def test_inline_policy_store_reads_writes_and_reprovisions():
    client = MagicMock()
    client.get_inline_policy_for_permission_set.return_value = {
        "InlinePolicy": json.dumps(DOC)
    }
    store = InlinePolicyStore(client, "ins", "ps")
    assert store.name == "inline-policy:ps"
    assert store.read() == DOC
    store.write(DOC)
    client.put_inline_policy_to_permission_set.assert_called_once_with(
        InstanceArn="ins", PermissionSetArn="ps", InlinePolicy=json.dumps(DOC)
    )
    client.provision_permission_set.assert_called_once_with(
        InstanceArn="ins", PermissionSetArn="ps", TargetType="ALL_PROVISIONED_ACCOUNTS"
    )


def test_inline_policy_store_can_skip_reprovisioning():
    client = MagicMock()
    InlinePolicyStore(client, "ins", "ps", provision=False).write(DOC)
    client.provision_permission_set.assert_not_called()
