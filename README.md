# idc-revoke

Revoke one IAM Identity Center user's live access by adding them to deny
lists that are already deployed, and take them out again later.

It never creates or attaches a policy. It only edits the value list of a
statement that already exists, so the policies themselves stay in your
landing zone pipeline.

## How it works

Temporary credentials can't be cancelled, but an explicit deny wins over
everything they are allowed to do. So you deploy, once, a deny statement
whose condition lists the revoked users (with a placeholder that matches
nobody). Revoking someone is then adding one value to that list.

The tool looks up the Identity Center user, adds their ID (or username)
to every list you configured, removes their direct account assignments
(so the portal stops offering the accounts; group assignments are
reported, not removed), and tells you what is left to do by hand.

It is built to be run under pressure:

- Every list is read and checked before anything is written. A wrong
  `sid`, an SCP or managed policy that would grow past its size limit,
  or an AWS error stops the run with "nothing was changed". (There is no
  size check for an inline policy: AWS refuses it at write time.)
- Each policy is read again just before it is written, so a change a
  colleague made in the meantime is kept.
- If a write then fails, the other policies are still written. The
  report lists what changed and what failed, and the exit code is 1. An
  error later in the run (listing assignments or groups) is added to
  the report, never shown in its place.
- Several lists in one policy (two statements of one SCP) are written in
  a single update.
- Running `revoke` again is safe. For an `inline_policy` list it
  reprovisions the permission set even when there is nothing to change,
  so a failed first provisioning can be repaired. `restore` does the
  same.
- `restore` exits with an error when it finds the user in none of the
  lists, which is what a mistyped `--user-id` looks like. It refuses an
  ID that belongs to another username.
- Interrupting a run (Ctrl-C) prints what was done so far.
- An assignment counts as removed, and an inline policy as changed, only
  once AWS confirms it.

## Policies

`policies/` holds the deny lists to deploy first, as an SCP or inside
your permission sets:

- `deny-list.json`: the deny on `identitystore:UserId`. It stops the
  sessions Identity Center gave out. It does not follow a role the user
  assumed from one of them.
- `deny-list-with-source-identity-guardrail.json`: the same, plus a
  guardrail that forces users to set a source identity equal to their
  username when they assume a role from an Identity Center session, and a
  second deny list on `aws:SourceIdentity` that follows them through
  every hop.
- `deny-list-with-all-guardrails.json`: the same, plus a statement that
  stops Identity Center roles from creating IAM users, access keys and
  console passwords.

Before you deploy the guardrail:

- Every role people chain into must allow `sts:SetSourceIdentity` in its
  trust policy, and callers must pass `--source-identity` (there is no
  CLI profile setting for it). Without that, the chain is refused.
- That refusal covers every `sts:AssumeRole` made from an Identity Center
  session: the console's Switch Role, and tools that assume a role for
  you (deployment roles, for example), stop working until they set a
  source identity.
- The guardrail statements match every Identity Center role
  (`aws-reserved/sso.amazonaws.com/*`). They were tested with that
  pattern narrowed to a few permission sets, not on a full landing zone.
  Narrow it the same way to roll it out gradually.
- SCPs do not apply to the management account. Put the deny list in the
  permission sets used there. The guardrail and the source identity list
  do not cover sessions in the management account either.
- If a pipeline owns your SCPs and reverts manual changes, edit the list
  in the permission sets and push the SCP change through the pipeline.

## Management account

SCPs do not apply to the management account, so a deny list in an SCP
never blocks a session there. The deny list has to sit in the permission
sets instead:

1. In the management account, create a customer managed IAM policy from
   `policies/deny-list.json`, for example `IdcRevokeDenyList`.
2. In IAM Identity Center, add a customer managed policy reference with
   that name to every permission set that is assigned on the management
   account.
3. Add the policy to your config:

```toml
[[deny_list]]
type = "managed_policy"
policy_arn = "arn:aws:iam::111111111111:policy/IdcRevokeDenyList"
sid = "DenyRevokedIdentityCenterUsers"
```

The tool then edits that policy like any other list. A customer managed
policy is read at each request, so the change needs no reprovisioning (in
a sandbox account a session was blocked about 8 seconds later).

Things to know:

- A permission set that references the policy fails to provision in an
  account where the policy does not exist. Create the policy in every
  account the permission set is assigned to before you add the
  reference.
- The deny matches one user ID, so other people on the same permission
  set are not affected. It does mean you can revoke yourself: run the
  tool as someone else, or from a permission set that does not reference
  the list.
- The `inline_policy` type works too, without a separate IAM policy, but
  each change reprovisions the permission set (about 12 seconds in the
  management account).

## Install and run

```bash
uv sync
uv run idc-revoke --config revoke.toml --dry-run revoke jane@example.com
uv run idc-revoke --config revoke.toml revoke jane@example.com
uv run idc-revoke --config revoke.toml status jane@example.com
uv run idc-revoke --config revoke.toml restore jane@example.com
```

`restore` accepts `--user-id` for a user deleted since the revocation.

## Try it without risk

Three things make a first run safe:

- `--dry-run` reads everything and changes nothing. The report shows
  which lists it would change.
- `status` only reads: it tells you, list by list, whether the user is in
  it.
- `restore` takes the user out of every list.

A first test on yourself, in a sandbox:

1. Deploy `policies/deny-list.json` as an SCP on one sandbox account (the
   placeholder in it matches nobody).
2. Copy `revoke.example.toml` to `revoke.toml` and fill in your identity
   store ID, instance ARN and the SCP's policy ID.
   Set `remove_assignments = false`, or the tool will remove your own
   account assignments.
3. Run `--dry-run revoke <you>`, then `revoke <you>`: your session in that
   account is denied a few seconds later.
4. Run `restore <you>` from a session the SCP does not cover (the
   management account), and your access comes back.

Do not test on your only way in: the SCP must not cover the session you
run the tool from.

## Permissions the tool needs

This list comes from the API calls in the code. I ran the tool as an
administrator, so it has not been checked against a role limited to
exactly these actions.

- Always: `identitystore:GetUserId`, `identitystore:DescribeUser`,
  `identitystore:ListGroupMembershipsForMember`,
  `identitystore:DescribeGroup`.
- Unless `remove_assignments = false`:
  `sso:ListAccountAssignmentsForPrincipal`,
  `sso:DeleteAccountAssignment`,
  `sso:DescribeAccountAssignmentDeletionStatus`.
- For an `scp` list: `organizations:DescribePolicy`,
  `organizations:UpdatePolicy`.
- For a `managed_policy` list, in the account that owns the policy:
  `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:ListPolicyVersions`,
  `iam:CreatePolicyVersion`, `iam:DeletePolicyVersion`. IAM keeps five
  versions of a policy: when all five exist, the tool deletes the oldest
  one that is not the default.
- For any list with a `role_arn`: `sts:AssumeRole` on that role.
- For an `inline_policy` list: `sso:GetInlinePolicyForPermissionSet`,
  `sso:PutInlinePolicyToPermissionSet`, `sso:ProvisionPermissionSet`,
  `sso:DescribePermissionSetProvisioningStatus`.

## Configuration

`revoke.example.toml` is a copy of this block to start from.

```toml
identity_store_id = "d-xxxxxxxxxx"
instance_arn = "arn:aws:sso:::instance/ssoins-xxxxxxxxxxxxxxxx"
region = "ca-central-1"
profile = "management"       # optional, default credentials otherwise
remove_assignments = true    # the default; direct assignments only
retention_hours = 12         # used to tell you when restore is safe

[[deny_list]]
type = "scp"
policy_id = "p-xxxxxxxx"
sid = "DenyRevokedIdentityCenterUsers"

[[deny_list]]                # same SCP, second list for chained sessions
type = "scp"
policy_id = "p-xxxxxxxx"
sid = "DenyRevokedSourceIdentities"
key = "aws:SourceIdentity"
template = "{user_name}"

[[deny_list]]
type = "managed_policy"
policy_arn = "arn:aws:iam::111111111111:policy/DenyList"
role_arn = "arn:aws:iam::111111111111:role/SomeAdminRole"  # or profile = "..."
sid = "DenyRevokedIdentityCenterUsers"

[[deny_list]]
type = "inline_policy"
permission_set_arn = "arn:aws:sso:::permissionSet/ssoins-xxx/ps-xxx"
sid = "DenyRevokedIdentityCenterUsers"
```

Each deny list takes `sid`, and optionally `key` (default
`identitystore:UserId`), `operator` (default `StringEquals`) and
`template` (default `{user_id}`; `{user_name}` is also available).

A list can also take `profile` or `role_arn` when its policy is in
another account, and an `inline_policy` list takes `provision = false`
to skip reprovisioning.

A customer managed policy exists once per account. If you created it in
ten accounts, the config needs ten `managed_policy` entries, each with
the `profile` or `role_arn` that reaches its account. An account without
an entry is not covered.

A setting the tool does not know, or a value of the wrong type, stops
the run: a typo in `remove_assignments` must not go unnoticed. A
`template` must contain `{user_id}` or `{user_name}`: a bare `*` would
deny everyone the policy covers. Two lists in the same policy must use
the same `profile`, `role_arn` and `provision`.

With `provision = false`, an inline policy is reported as changed but
has no effect until you reprovision the permission set yourself.

Put `scp` and `managed_policy` lists before `inline_policy` lists: they
are written in the order of the file, and an inline policy waits for its
reprovisioning (up to two minutes) before the next one starts.

## Use as a module

```python
import boto3
from idc_revoke import DenyList, Revoker, ScpStore

session = boto3.Session(profile_name="management")
revoker = Revoker(
    identitystore=session.client("identitystore"),
    identity_store_id="d-xxxxxxxxxx",
    deny_lists=[
        DenyList(
            ScpStore(session.client("organizations"), "p-xxxxxxxx"),
            sid="DenyRevokedIdentityCenterUsers",
        ),
    ],
)
report = revoker.revoke("jane@example.com")
print(report.restore_after, report.manual_steps)
```

A deny list can live anywhere: write a class with a `name` and `read()`
and `write(document)` methods and pass it as the store. Two lists in the
same policy must share the same store name: the policy is then read
once and written once.

Used as a module, `Revoker` keeps account assignments unless you pass
`remove_assignments=True` with an `sso_admin` client and `instance_arn`.
Only the command line removes them by default.

## What it does not do

- Give assignments back: `restore` only empties the deny lists. The
  assignments `revoke` removed are listed in its report, to recreate by
  hand. Set `remove_assignments = false` to keep them.
- End portal sessions or disable the user: there is no API.
- Remove group memberships: they are listed in the report.
- Find IAM users, keys or chained roles the person left behind.
- Schedule its own clean-up: run `restore` yourself. Do it only once
  the user is disabled, their portal session has ended, their
  assignments and group memberships are gone, and the longest session
  duration has passed. Before that, the portal can hand them fresh
  credentials the moment they leave the list.

## Known limits

- With the source identity guardrail deployed, a `role_arn` in the
  config is refused when the tool runs from an Identity Center session
  in a member account, because the tool does not set a source identity
  on that hop. It fails before changing anything. Run it from the
  management account, or use a `profile` per account.
- Two people writing the same policy within the same second or two can
  still overwrite each other: the last write wins. Run `status`
  afterwards.
- A user already deleted from Identity Center cannot be revoked or
  checked: `revoke` and `status` look the user up by name. Only
  `restore` takes `--user-id`. Revoke before you delete.
- The AWS documentation says the listing of a user's assignments must be
  called from the management account. Running from a delegated
  administrator account was not tested.
- Usernames are matched without regard to case when the user is looked
  up, and the tool then uses the exact username Identity Center stores.
  The lists on a username are case sensitive.

## Develop

```bash
uv run pytest -q
uv run ruff format . && uv run ruff check .
```

## License

MIT, see `LICENSE`.
