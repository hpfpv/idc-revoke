"""Revoke and restore one IAM Identity Center user through deny lists."""

import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from idc_revoke.policy import Document, add_value, list_values, remove_value
from idc_revoke.stores import DenyListStore, compact

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


class PreflightError(ValueError):
    """A deny list cannot be edited. Raised before anything is written."""


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
        try:
            return self.template.format(user_id=user.user_id, user_name=user.user_name)
        except (KeyError, IndexError) as error:
            raise ValueError(
                f"unknown placeholder in template {self.template!r} "
                "(use {user_id} or {user_name})"
            ) from error

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
    failed: list[str] = field(default_factory=list)
    removed_assignments: list[str] = field(default_factory=list)
    inherited_assignments: list[str] = field(default_factory=list)
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
        sleep: Callable[[float], None] = time.sleep,
        poll_attempts: int = 40,
        poll_interval: float = 1.5,
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
        self.sleep = sleep
        self.poll_attempts = poll_attempts
        self.poll_interval = poll_interval

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
        # GetUserId ignores case, but the lists on the user name do not.
        described = self.identitystore.describe_user(
            IdentityStoreId=self.identity_store_id, UserId=found["UserId"]
        )
        return User(found["UserId"], described.get("UserName") or user_name)

    def revoke(self, user_name: str) -> RevokeReport:
        """Deny the user everywhere, then optionally remove assignments."""
        user = self.find_user(user_name)
        report = RevokeReport(user, "revoke", self.dry_run)
        self._apply(report, add=True)
        # From here the lists are written: whatever fails, keep the report.
        if self.remove_assignments:
            self._remove_assignments(user, report)
        try:
            report.groups = self._group_names(user)
        except (BotoCoreError, ClientError) as error:
            report.failed.append(f"listing groups: {error}")
        report.restore_after = self.clock() + self.retention
        report.manual_steps = list(MANUAL_STEPS)
        return report

    def restore(self, user_name: str, user_id: str | None = None) -> RevokeReport:
        """Take the user out of every deny list.

        Pass ``user_id`` when the user has been deleted since the revocation.
        """
        if user_id:
            user = User(user_id, self._stored_name(user_id) or user_name)
        else:
            user = self.find_user(user_name)
        report = RevokeReport(user, "restore", self.dry_run)
        self._apply(report, add=False)
        return report

    def _stored_name(self, user_id: str) -> str | None:
        """The user name Identity Center holds, if the user still exists."""
        try:
            described = self.identitystore.describe_user(
                IdentityStoreId=self.identity_store_id, UserId=user_id
            )
        except ClientError:
            return None
        return described.get("UserName")

    def status(self, user_name: str) -> dict[str, bool]:
        """Say, for each deny list, whether the user is in it."""
        user = self.find_user(user_name)
        return {
            deny_list.label: deny_list.holds(deny_list.store.read(), user)
            for deny_list in self.deny_lists
        }

    def _apply(self, report: RevokeReport, add: bool) -> None:
        """Check every policy first, then write each one once.

        Several lists can sit in one policy (two statements of one SCP), so
        the lists are grouped by store: one read, every edit, one write.
        """
        stores: dict[str, list[DenyList]] = {}
        for deny_list in self.deny_lists:
            stores.setdefault(deny_list.store.name, []).append(deny_list)
        plan = []
        for deny_lists in stores.values():
            store, label = deny_lists[0].store, deny_lists[0].store.name
            touched: list[DenyList] = []
            try:
                document = store.read()
                for deny_list in deny_lists:
                    label = deny_list.label
                    if deny_list.holds(document, report.user) != add:
                        edit = deny_list.with_user if add else deny_list.without_user
                        document = edit(document, report.user)
                        touched.append(deny_list)
                if touched:
                    self._check_size(store, document)
            except (LookupError, ValueError, BotoCoreError, ClientError) as error:
                raise PreflightError(
                    f"nothing was changed: {label}: {error}"
                ) from error
            plan.append((store, document, deny_lists, touched))
        for store, document, deny_lists, touched in plan:
            untouched = [item.label for item in deny_lists if item not in touched]
            report.unchanged.extend(untouched)
            # A store such as an inline policy must be applied again on a
            # re-run: the document can be right while the roles are not.
            action = store.write if touched else getattr(store, "ensure", None)
            labels = [item.label for item in touched] or untouched
            if action and not self.dry_run:
                try:
                    action(document) if touched else action()
                except Exception as error:  # one policy must not stop the others
                    report.failed.extend(f"{label}: {error}" for label in labels)
                    continue
            report.changed.extend(item.label for item in touched)

    @staticmethod
    def _check_size(store: DenyListStore, document: Document) -> None:
        limit = getattr(store, "max_size", None)
        size = len(compact(document))
        if limit and size > limit:
            raise ValueError(
                f"the policy would be {size} characters, over the limit of {limit}"
            )

    def _remove_assignments(self, user: User, report: RevokeReport) -> None:
        """Delete the user's direct account assignments (not group ones)."""
        pending: list[tuple[str, str]] = []
        request = {
            "InstanceArn": self.instance_arn,
            "PrincipalId": user.user_id,
            "PrincipalType": "USER",
        }
        try:
            while True:
                page = self.sso_admin.list_account_assignments_for_principal(**request)
                for item in page["AccountAssignments"]:
                    label = f"{item['AccountId']}/{item['PermissionSetArn']}"
                    # The listing also returns what is held through a group.
                    if item.get("PrincipalType", "USER") != "USER":
                        report.inherited_assignments.append(label)
                    elif self.dry_run:
                        report.removed_assignments.append(label)
                    else:
                        self._delete_assignment(user, item, label, report, pending)
                if "NextToken" not in page:
                    break
                request["NextToken"] = page["NextToken"]
        except (BotoCoreError, ClientError) as error:
            report.failed.append(f"listing assignments: {error}")
        for label, request_id in pending:
            try:
                outcome = self._deletion_outcome(request_id)
            except (BotoCoreError, ClientError) as error:
                outcome = str(error)
            if outcome is None:
                report.removed_assignments.append(label)
            else:
                report.failed.append(f"assignment {label}: {outcome}")

    def _delete_assignment(
        self,
        user: User,
        item: dict[str, Any],
        label: str,
        report: RevokeReport,
        pending: list[tuple[str, str]],
    ) -> None:
        try:
            started = self.sso_admin.delete_account_assignment(
                InstanceArn=self.instance_arn,
                TargetId=item["AccountId"],
                TargetType="AWS_ACCOUNT",
                PermissionSetArn=item["PermissionSetArn"],
                PrincipalType="USER",
                PrincipalId=user.user_id,
            )
        except (BotoCoreError, ClientError) as error:
            report.failed.append(f"assignment {label}: {error}")
            return
        pending.append((label, started["AccountAssignmentDeletionStatus"]["RequestId"]))

    def _deletion_outcome(self, request_id: str) -> str | None:
        """None when the deletion succeeded, otherwise what went wrong."""
        for attempt in range(self.poll_attempts):
            status = self.sso_admin.describe_account_assignment_deletion_status(
                InstanceArn=self.instance_arn,
                AccountAssignmentDeletionRequestId=request_id,
            )["AccountAssignmentDeletionStatus"]
            if status["Status"] == "SUCCEEDED":
                return None
            if status["Status"] != "IN_PROGRESS":
                reason = status.get("FailureReason", "no reason given")
                return f"{status['Status']}: {reason}"
            if attempt < self.poll_attempts - 1:
                self.sleep(self.poll_interval)
        return "still in progress"

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
