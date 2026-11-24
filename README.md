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
to every list you configured, removes their direct account assignments,
and tells you what is left to do by hand.

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
- The guardrail statements match every Identity Center role
  (`aws-reserved/sso.amazonaws.com/*`). They were tested with that
  pattern narrowed to a few permission sets, not on a full landing zone.
  Narrow it the same way to roll it out gradually.
- SCPs do not apply to the management account. Put the deny list in the
  permission sets used there.
- If a pipeline owns your SCPs and reverts manual changes, edit the list
  in the permission sets and push the SCP change through the pipeline.

## Install and run

```bash
uv sync
uv run idc-revoke --config revoke.toml --dry-run revoke jane@example.com
uv run idc-revoke --config revoke.toml revoke jane@example.com
uv run idc-revoke --config revoke.toml status jane@example.com
uv run idc-revoke --config revoke.toml restore jane@example.com
```

`restore` accepts `--user-id` for a user deleted since the revocation.

## Configuration

```toml
identity_store_id = "d-xxxxxxxxxx"
instance_arn = "arn:aws:sso:::instance/ssoins-xxxxxxxxxxxxxxxx"
region = "ca-central-1"
profile = "management"       # optional, default credentials otherwise
remove_assignments = true    # direct assignments only, groups are reported
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
and `write(document)` methods and pass it as the store.

## What it does not do

- End portal sessions or disable the user: there is no API.
- Remove group memberships: they are listed in the report.
- Find IAM users, keys or chained roles the person left behind.
- Schedule its own clean-up: run `restore` after the longest session
  duration.

## Develop

```bash
uv run pytest -q
uv run ruff format . && uv run ruff check .
```

## License

MIT, see `LICENSE`.
