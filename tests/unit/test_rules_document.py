"""Text-block document: byte-identical round trip, comment ownership, edits."""

from __future__ import annotations

import pytest

from app.rules.document import DocumentError, RulesDocument
from app.rules.form import FormError, RuleForm, apply_form
from scripts.split_config import split

SIMPLE = """access_control:
  default_policy: deny  # keep closed

  rules:
    # first rule note
    - domain: a.example.com
      policy: bypass    # inline note
      resources:
        - '^/x$'
#        - "^/commented-out$"

    # second rule note (line 1)
    # second rule note (line 2)
    - domain: "b.example.com"
      subject:
        - ['group:admin']
      policy: two_factor

    - domain: c.example.com
      policy: deny
"""


@pytest.fixture
def realistic_ac(realistic_main: str) -> str:
    return split(realistic_main).access_control_text


def test_round_trip_is_byte_identical(realistic_ac: str) -> None:
    for text in (SIMPLE, realistic_ac):
        assert RulesDocument.parse(text).render() == text


def test_blocks_own_their_attached_comments() -> None:
    doc = RulesDocument.parse(SIMPLE)
    assert len(doc.blocks) == 3
    assert doc.blocks[0].note == "first rule note"
    assert doc.blocks[1].note == "second rule note (line 1)\nsecond rule note (line 2)"
    assert doc.blocks[0].has_inner_comments and not doc.blocks[2].has_inner_comments
    # the commented-out path stays with its rule, not with the next one
    assert any("commented-out" in line for line in doc.blocks[0].lines)
    assert not any("commented-out" in line for line in doc.blocks[1].lines)


def test_data_and_default_policy() -> None:
    doc = RulesDocument.parse(SIMPLE)
    assert doc.default_policy() == "deny"
    assert [r["domain"] for r in doc.rules()] == ["a.example.com", "b.example.com", "c.example.com"]
    assert doc.effective()["access_control"]["rules"][1]["subject"] == [["group:admin"]]


def test_move_carries_notes_and_comments() -> None:
    moved = RulesDocument.parse(SIMPLE).move(0, 2)
    text = moved.render()
    assert [r["domain"] for r in moved.rules()] == [
        "b.example.com",
        "c.example.com",
        "a.example.com",
    ]
    lines = text.splitlines()
    note_at = lines.index("    # first rule note")
    assert lines[note_at + 1].strip() == "- domain: a.example.com"
    assert text.count("commented-out") == 1
    assert RulesDocument.parse(text).render() == text  # still parses and is stable


def test_delete_and_range_errors() -> None:
    doc = RulesDocument.parse(SIMPLE)
    assert [r["domain"] for r in doc.delete(1).rules()] == ["a.example.com", "c.example.com"]
    with pytest.raises(DocumentError):
        doc.delete(3)
    with pytest.raises(DocumentError):
        doc.move(0, 9)


def test_default_policy_edit_keeps_inline_comment() -> None:
    text = RulesDocument.parse(SIMPLE).with_default_policy("one_factor").render()
    assert "  default_policy: one_factor  # keep closed" in text


def test_editing_one_rule_leaves_all_others_untouched(realistic_ac: str) -> None:
    doc = RulesDocument.parse(realistic_ac)
    node = doc.blocks[2].node()
    node["policy"] = "one_factor"
    edited = doc.replace_rule(2, node)
    assert [b.lines for i, b in enumerate(edited.blocks) if i != 2] == [
        b.lines for i, b in enumerate(doc.blocks) if i != 2
    ]
    new_block = "\n".join(edited.blocks[2].lines)
    assert "policy: one_factor" in new_block
    assert '"^/api/.*"' in new_block  # quoting preserved
    assert "frontend_latest" in new_block  # commented-out path survives the edit
    assert [r["domain"] for r in RulesDocument.parse(edited.render()).rules()] == [
        r["domain"] for r in doc.rules()
    ]


def test_form_edit_keeps_untouched_keys_and_unknown_keys() -> None:
    doc = RulesDocument.parse(SIMPLE + "      x_custom: 7\n")
    form = RuleForm.from_data(doc.rules()[2], note="")
    form.policy = "one_factor"
    edited = doc.replace_rule(2, apply_form(form, doc.blocks[2].node()))
    assert edited.rules()[2] == {"domain": "c.example.com", "policy": "one_factor", "x_custom": 7}


def test_form_adds_keys_before_policy_and_inserts_with_note() -> None:
    doc = RulesDocument.parse(SIMPLE)
    form = RuleForm(domain=["new.example.com"], resources=["^/api/"], policy="bypass", note="added")
    inserted = doc.insert(1, apply_form(form), note=form.note)
    text = inserted.render()
    assert [r["domain"] for r in inserted.rules()][1] == "new.example.com"
    assert list(inserted.rules()[1]) == ["domain", "resources", "policy"]
    assert "    # added\n    - domain: new.example.com" in text
    assert RulesDocument.parse(text).render() == text


def test_form_clearing_lists_removes_keys() -> None:
    doc = RulesDocument.parse(SIMPLE)
    form = RuleForm.from_data(doc.rules()[0])
    form.resources = []
    rule = RulesDocument.parse(doc.replace_rule(0, apply_form(form, doc.blocks[0].node())).render())
    assert "resources" not in rule.rules()[0]


def test_flat_subject_list_is_not_rewritten_when_unchanged() -> None:
    text = SIMPLE.replace("[ 'group:admin' ]", "").replace("- ['group:admin']", "- 'group:admin'")
    doc = RulesDocument.parse(text)
    form = RuleForm.from_data(doc.rules()[1])
    edited = doc.replace_rule(1, apply_form(form, doc.blocks[1].node()))
    assert "- 'group:admin'" in "\n".join(edited.blocks[1].lines)


@pytest.mark.parametrize(
    ("form", "message"),
    [
        (RuleForm(policy="bypass"), "domain"),
        (RuleForm(domain=["a.example.com"], policy="allow"), "Policy"),
        (RuleForm(domain=["a.example.com"], extra_yaml="- not a mapping"), "mapping"),
        (RuleForm(domain=["a.example.com"], extra_yaml="policy: deny"), "repeat"),
        (RuleForm(domain=["a.example.com"], query_yaml="a: [unclosed"), "YAML"),
    ],
)
def test_form_validation(form: RuleForm, message: str) -> None:
    with pytest.raises(FormError, match=message):
        apply_form(form)


def test_empty_and_invalid_documents() -> None:
    empty = RulesDocument.parse("access_control:\n  default_policy: deny\n  rules: []\n")
    assert empty.rules() == []
    added = empty.insert(0, apply_form(RuleForm(domain=["a.example.com"], policy="deny")))
    assert added.rules()[0]["domain"] == "a.example.com"
    with pytest.raises(DocumentError):
        RulesDocument.parse("session:\n  secret: x\n")
    with pytest.raises(DocumentError):
        RulesDocument.parse("a: [unclosed\n")


def test_default_policy_is_found_by_the_parser_not_by_a_line_regex() -> None:
    """Review finding: a `default_policy:` line elsewhere must not be mistaken for ours."""
    text = (
        "authorization_policies:\n  p:\n    default_policy: two_factor\n"
        "access_control:\n  default_policy: deny\n  rules:\n"
        "    - domain: a.example.com\n      policy: bypass\n"
    )
    doc = RulesDocument.parse(text)
    assert doc.default_policy() == "deny"
    out = doc.with_default_policy("one_factor").render()
    assert "    default_policy: two_factor" in out and "  default_policy: one_factor" in out


def test_missing_default_policy_means_deny_and_cannot_be_set_blindly() -> None:
    doc = RulesDocument.parse(
        "access_control:\n  rules:\n    - {domain: a.example.com, policy: deny}\n"
    )
    assert doc.default_policy() == "deny"
    with pytest.raises(DocumentError):
        doc.with_default_policy("bypass")


@pytest.mark.parametrize("char", ["\u2028", "\u2029", "\x85", "\x0c"])
def test_unusual_line_breaks_are_refused(char: str) -> None:
    """They would desync our line handling from the YAML parser and change data on write."""
    text = (
        "access_control:\n  default_policy: deny\n  rules:\n"
        f"    - domain: 'a{char}b.example.com'\n      policy: deny\n"
    )
    with pytest.raises(DocumentError, match="line-break"):
        RulesDocument.parse(text)
