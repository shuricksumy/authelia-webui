from app.config_merge import deep_merge, merge_all


def test_maps_merge_recursively() -> None:
    base = {"oidc": {"hmac": "a", "clients": [1]}, "keep": 1}
    assert deep_merge(base, {"oidc": {"scopes": {"x": 1}}}) == {
        "oidc": {"hmac": "a", "clients": [1], "scopes": {"x": 1}},
        "keep": 1,
    }


def test_lists_are_replaced_not_appended() -> None:
    assert deep_merge({"rules": [1, 2]}, {"rules": [3]}) == {"rules": [3]}


def test_later_scalar_wins_and_inputs_are_not_mutated() -> None:
    base = {"a": {"b": 1}}
    merged = deep_merge(base, {"a": {"b": 2}})
    assert merged == {"a": {"b": 2}} and base == {"a": {"b": 1}}


def test_merge_all_skips_empty_documents() -> None:
    assert merge_all([{"a": 1}, None, {}, {"b": 2}]) == {"a": 1, "b": 2}
