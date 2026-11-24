import copy

import pytest

from idc_revoke.policy import (
    PLACEHOLDER,
    StatementNotFoundError,
    add_value,
    list_values,
    remove_value,
)

SID = "DenyRevoked"
OP = "StringEquals"
KEY = "identitystore:UserId"


def make_doc(values="KEEP-ME"):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "Other", "Effect": "Deny", "Action": "s3:*", "Resource": "*"},
            {
                "Sid": SID,
                "Effect": "Deny",
                "Action": "*",
                "Resource": "*",
                "Condition": {OP: {"identitystore:userid": values}},
            },
        ],
    }


def test_list_values_normalises_a_single_string():
    assert list_values(make_doc("one"), SID, OP, KEY) == ["one"]


def test_add_value_appends_and_does_not_mutate_the_input():
    doc = make_doc(["a"])
    before = copy.deepcopy(doc)
    out = add_value(doc, SID, OP, KEY, "b")
    assert list_values(out, SID, OP, KEY) == ["a", "b"]
    assert doc == before


def test_add_value_is_idempotent():
    out = add_value(make_doc(["a"]), SID, OP, KEY, "a")
    assert list_values(out, SID, OP, KEY) == ["a"]


def test_add_value_keeps_the_key_spelling_already_in_the_policy():
    out = add_value(make_doc(["a"]), SID, OP, KEY, "b")
    assert list(out["Statement"][1]["Condition"][OP]) == ["identitystore:userid"]


def test_remove_value_removes_only_that_value():
    out = remove_value(make_doc(["a", "b"]), SID, OP, KEY, "a")
    assert list_values(out, SID, OP, KEY) == ["b"]


def test_remove_last_value_leaves_a_placeholder():
    out = remove_value(make_doc(["a"]), SID, OP, KEY, "a")
    assert list_values(out, SID, OP, KEY) == [PLACEHOLDER]


def test_remove_missing_value_changes_nothing():
    doc = make_doc(["a"])
    assert remove_value(doc, SID, OP, KEY, "zzz") == doc


def test_single_statement_object_is_supported():
    doc = make_doc(["a"])
    doc["Statement"] = doc["Statement"][1]
    out = add_value(doc, SID, OP, KEY, "b")
    assert list_values(out, SID, OP, KEY) == ["a", "b"]


@pytest.mark.parametrize(
    ("sid", "operator", "key"),
    [("Nope", OP, KEY), (SID, "StringLike", KEY), (SID, OP, "aws:userid")],
)
def test_missing_statement_operator_or_key_raises(sid, operator, key):
    with pytest.raises(StatementNotFoundError):
        add_value(make_doc(), sid, operator, key, "x")
