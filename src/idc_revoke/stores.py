"""Where a deny list lives: an SCP, a managed policy or an inline policy.

A store only reads and writes a whole policy document. Write your own by
giving it a ``name`` and ``read`` and ``write`` methods.
"""

import json
from dataclasses import dataclass
from typing import Any, Protocol

from idc_revoke.policy import Document


class DenyListStore(Protocol):
    """Anything that can load and save one policy document."""

    name: str

    def read(self) -> Document: ...

    def write(self, document: Document) -> None: ...


@dataclass
class ScpStore:
    """A service control policy. Fastest to take effect (1 to 2 s in the lab).

    It never applies to the management account.
    """

    client: Any  # boto3 "organizations" client
    policy_id: str

    @property
    def name(self) -> str:
        return f"scp:{self.policy_id}"

    def read(self) -> Document:
        policy = self.client.describe_policy(PolicyId=self.policy_id)
        return json.loads(policy["Policy"]["Content"])

    def write(self, document: Document) -> None:
        self.client.update_policy(PolicyId=self.policy_id, Content=json.dumps(document))


@dataclass
class ManagedPolicyStore:
    """A customer managed policy in one account, referenced by permission sets.

    Editing it takes effect without reprovisioning (about 8 s in the lab).
    IAM keeps five versions at most, so the oldest one is pruned when full:
    https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html
    """

    client: Any  # boto3 "iam" client for the account that holds the policy
    policy_arn: str
    max_versions: int = 5

    @property
    def name(self) -> str:
        return f"managed-policy:{self.policy_arn}"

    def read(self) -> Document:
        policy = self.client.get_policy(PolicyArn=self.policy_arn)
        version = self.client.get_policy_version(
            PolicyArn=self.policy_arn,
            VersionId=policy["Policy"]["DefaultVersionId"],
        )
        document = version["PolicyVersion"]["Document"]
        return json.loads(document) if isinstance(document, str) else document

    def write(self, document: Document) -> None:
        versions = self.client.list_policy_versions(PolicyArn=self.policy_arn)
        versions = versions["Versions"]
        if len(versions) >= self.max_versions:
            spare = [v for v in versions if not v["IsDefaultVersion"]]
            oldest = min(spare, key=lambda v: v["CreateDate"])
            self.client.delete_policy_version(
                PolicyArn=self.policy_arn, VersionId=oldest["VersionId"]
            )
        self.client.create_policy_version(
            PolicyArn=self.policy_arn,
            PolicyDocument=json.dumps(document),
            SetAsDefault=True,
        )


@dataclass
class InlinePolicyStore:
    """The inline policy of one permission set.

    A change does nothing until the permission set is reprovisioned, so this
    store reprovisions on write unless told not to.
    """

    client: Any  # boto3 "sso-admin" client
    instance_arn: str
    permission_set_arn: str
    provision: bool = True

    @property
    def name(self) -> str:
        return f"inline-policy:{self.permission_set_arn}"

    def read(self) -> Document:
        policy = self.client.get_inline_policy_for_permission_set(
            InstanceArn=self.instance_arn, PermissionSetArn=self.permission_set_arn
        )
        return json.loads(policy["InlinePolicy"])

    def write(self, document: Document) -> None:
        self.client.put_inline_policy_to_permission_set(
            InstanceArn=self.instance_arn,
            PermissionSetArn=self.permission_set_arn,
            InlinePolicy=json.dumps(document),
        )
        if self.provision:
            self.client.provision_permission_set(
                InstanceArn=self.instance_arn,
                PermissionSetArn=self.permission_set_arn,
                TargetType="ALL_PROVISIONED_ACCOUNTS",
            )
