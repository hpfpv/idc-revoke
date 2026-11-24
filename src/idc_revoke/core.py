"""Revoke and restore one IAM Identity Center user through deny lists."""

from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import ClientError

from idc_revoke.policy import Document, add_value, list_values, remove_value
from idc_revoke.stores import DenyListStore

MANUAL_STEPS = [
    "End the user's sessions in the Identity Center console (Active sessions).",
    "Disable the user in the identity provider.",
    "Remove the user from the groups listed in this report.",
    "Search CloudTrail for IAM users, access keys and roles the user created, "
    "and for every AssumeRole the user made.",
    "Revoke sessions on any role the user chained into and delete any key.",
    "Run restore once the longest session duration has passed.",
]


class UserNotFoundError(LookupError):
    """No Identity Center user has that user name."""


@dataclass(frozen=True)
class User:
    user_id: str
    user_name: str


@dataclass
class DenyList:
    """One list of denied values inside one statement of one policy.

    The template decides what goes in the list. ``{user_id}`` suits
    ``identitystore:UserId``; ``*:{user_name}`` suits ``aws:userid``;
    ``{user_name}`` suits ``aws:SourceIdentity``.
    """

    store: DenyListStore
    sid: str
    key: str = "identitystore:UserId"
    operator: str = "StringEquals"
    template: str = "{user_id}"

    @property
    def label(self) -> str:
        return f"{self.store.name}/{self.sid}"

    def value_for(self, user: User) -> str:
        return self.template.format(user_id=user.user_id, user_name=user.user_name)

    def holds(self, document: Document, user: User) -> bool:
        values = list_values(document, self.sid, self.operator, self.key)
        return self.value_for(user) in values

    def with_user(self, document: Document, user: User) -> Document:
        return add_value(
            document, self.sid, self.operator, self.key, self.value_for(user)
        )

    def without_user(self, document: Document, user: User) -> Document:
        return remove_value(
            document, self.sid, self.operator, self.key, self.value_for(user)
        )


@dataclass
class RevokeReport:
    user: User
    action: str
    dry_run: bool
    changed: list[str] = field(default_factory=list)
    unchanged: list[str] = field(default_factory=list)
    removed_assignments: list[str] = field(default_factory=list)
    groups: list[str] = field(default_factory=list)
    restore_after: datetime | None = None
    manual_steps: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        if self.restore_after is not None:
            data["restore_after"] = self.restore_after.isoformat()
        return data


class Revoker:
    """Adds a user to every deny list, and takes them out again later.

    Clients are passed in, so the caller decides credentials, regions and
    accounts. Nothing is created or attached: the deny lists must exist.
    """

    def __init__(
        self,
        identitystore: Any,
        identity_store_id: str,
        deny_lists: list[DenyList],
        sso_admin: Any = None,
        instance_arn: str | None = None,
        remove_assignments: bool = False,
        retention: timedelta = timedelta(hours=12),
        dry_run: bool = False,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.identitystore = identitystore
        self.identity_store_id = identity_store_id
        self.deny_lists = deny_lists
        self.sso_admin = sso_admin
        self.instance_arn = instance_arn
        self.remove_assignments = remove_assignments
        self.retention = retention
        self.dry_run = dry_run
        self.clock = clock

    def find_user(self, user_name: str) -> User:
        try:
            found = self.identitystore.get_user_id(
                IdentityStoreId=self.identity_store_id,
                AlternateIdentifier={
                    "UniqueAttribute": {
                        "AttributePath": "userName",
                        "AttributeValue": user_name,
                    }
                },
            )
        except ClientError as error:
            if error.response["Error"]["Code"] == "ResourceNotFoundException":
                raise UserNotFoundError(user_name) from error
            raise
        return User(found["UserId"], user_name)

    def revoke(self, user_name: str) -> RevokeReport:
        """Deny the user everywhere, then optionally remove assignments."""
        user = self.find_user(user_name)
        report = RevokeReport(user, "revoke", self.dry_run)
        self._apply(report, add=True)
        if self.remove_assignments:
            report.removed_assignments = self._remove_assignments(user)
        report.groups = self._group_names(user)
        report.restore_after = self.clock() + self.retention
        report.manual_steps = list(MANUAL_STEPS)
        return report

    def restore(self, user_name: str, user_id: str | None = None) -> RevokeReport:
        """Take the user out of every deny list.

        Pass ``user_id`` when the user has been deleted since the revocation.
        """
        user = User(user_id, user_name) if user_id else self.find_user(user_name)
        report = RevokeReport(user, "restore", self.dry_run)
        self._apply(report, add=False)
        return report

    def status(self, user_name: str) -> dict[str, bool]:
        """Say, for each deny list, whether the user is in it."""
        user = self.find_user(user_name)
        return {
            deny_list.label: deny_list.holds(deny_list.store.read(), user)
            for deny_list in self.deny_lists
        }

    def _apply(self, report: RevokeReport, add: bool) -> None:
        for deny_list in self.deny_lists:
            current = deny_list.store.read()
            if deny_list.holds(current, report.user) == add:
                report.unchanged.append(deny_list.label)
                continue
            edit = deny_list.with_user if add else deny_list.without_user
            if not self.dry_run:
                deny_list.store.write(edit(current, report.user))
            report.changed.append(deny_list.label)

    def _remove_assignments(self, user: User) -> list[str]:
        """Delete the user's direct account assignments (not group ones)."""
        removed = []
        request = {
            "InstanceArn": self.instance_arn,
            "PrincipalId": user.user_id,
            "PrincipalType": "USER",
        }
        while True:
            page = self.sso_admin.list_account_assignments_for_principal(**request)
            for item in page["AccountAssignments"]:
                if not self.dry_run:
                    self.sso_admin.delete_account_assignment(
                        InstanceArn=self.instance_arn,
                        TargetId=item["AccountId"],
                        TargetType="AWS_ACCOUNT",
                        PermissionSetArn=item["PermissionSetArn"],
                        PrincipalType="USER",
                        PrincipalId=user.user_id,
                    )
                removed.append(f"{item['AccountId']}/{item['PermissionSetArn']}")
            if "NextToken" not in page:
                return removed
            request["NextToken"] = page["NextToken"]

    def _group_names(self, user: User) -> list[str]:
        names = []
        request = {
            "IdentityStoreId": self.identity_store_id,
            "MemberId": {"UserId": user.user_id},
        }
        while True:
            page = self.identitystore.list_group_memberships_for_member(**request)
            for membership in page["GroupMemberships"]:
                group = self.identitystore.describe_group(
                    IdentityStoreId=self.identity_store_id,
                    GroupId=membership["GroupId"],
                )
                names.append(group["DisplayName"])
            if "NextToken" not in page:
                return names
            request["NextToken"] = page["NextToken"]
