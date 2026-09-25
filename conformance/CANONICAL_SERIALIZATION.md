# Custos canonical serialization — normative spec

This is the byte-level contract every implementation of Custos must match. If
two implementations disagree on these bytes, every signature fails and the
protocol has no cross-language existence. It is implemented in
`custos_protocol/canonical.py` (`canonical_bytes` / `get_signable_payload`) and
pinned by `tests/test_canonical.py` and every `serialization` vector in
`vectors.json`.

## Relationship to RFC 8785 (JCS)

Custos's canonical form is **not** RFC 8785 (JSON Canonicalization Scheme). It
borrows RFC 8785's approach (recursive key sorting, no insignificant
whitespace) but diverges on number handling, which is the part every
implementer must get exactly right:

- RFC 8785 canonicalizes numbers per ECMA-262's `Number::toString`, which has
  no concept of "this integer-valued float should serialize without a decimal
  point" beyond what IEEE-754 double formatting already does, and has no
  concept of arbitrary-precision decimals at all.
- Custos instead relies on **Pydantic pre-converting every `Decimal` field to
  a JSON *string*** before this module ever sees it (rule 6 below), and
  applies its own whole-float-to-int rule (rule 2) as a separate, explicit
  step — not inherited from any RFC 8785 number-formatting behavior.

**A second-language implementation must reproduce this specific pipeline**
(decimal → string, at the model layer, before serialization; whole float →
int, as an explicit post-processing step) rather than reach for a generic
RFC 8785 library and assume it is equivalent. This is the single most likely
point of divergence for a new implementation — verified against the
`serialization` category vectors (`K01`–`K05`) before touching anything else.

## The algorithm

```
canonical_bytes(data: dict, exclude: set[str]) -> bytes:
    1. filtered = {k: v for k, v in data.items() if k not in exclude}
    2. normalized = normalize_numbers(filtered)      # rule 2, recursive
    3. return json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")

get_signable_payload(model, exclude) -> bytes:
    return canonical_bytes(model.model_dump(mode="json", by_alias=True), exclude)
```

`canonical_bytes` operates on a plain `dict` — this is the verifier's entry
point, since a relying party receives JSON off the wire, not a Python model.
`get_signable_payload` dumps a model and delegates to it, so a signer and a
verifier in the same process provably share one implementation. A
second-language implementation only needs to reproduce `canonical_bytes`;
there is no model layer to match.

## The eight rules

| # | Rule | Failure it prevents |
|---|---|---|
| 1 | **Exclude `proof`** (and any other signature/key field the caller names) | Circularity — you cannot sign your own signature. `canonicalize` only strips excluded keys at the **top level**; a nested field named `proof` is not excluded and would be signed. Name every top-level field that must never participate. |
| 2 | **Whole floats become ints** (`500.0` → `500`) | Python emits `500.0`, JavaScript emits `500` for the same numeric value. Different bytes → different signature → total interop failure. `bool` is checked *before* `int`/`float` (it is a subclass of `int` in Python) so `True`/`False` never collapse to `1`/`0`. Non-finite values (`NaN`, `±Infinity`) raise `NonFiniteNumberError` rather than producing JSON's non-standard `NaN`/`Infinity` tokens. |
| 3 | **Keys sorted recursively, lexicographically by UTF-16 code unit** (Python `str` comparison, which matches JavaScript's default string sort for the ASCII range these keys use) | Dict/object key ordering differs across languages and even across runs. `@context` sorts before `action` because `@` is `U+0040`, before every ASCII letter. |
| 4 | **No whitespace** (`separators=(",", ":")`) | Pretty-printing differences between implementations. |
| 5 | **UTF-8 bytes** | Encoding ambiguity; the final output is bytes, not a `str`, specifically so "what encoding" is never a second question. |
| 6 | **`Decimal` fields serialize as JSON strings**, done by Pydantic's `mode="json"` before this module runs, not by anything in `canonical.py` itself | Exactness. `Decimal("50000.00")` becomes the four-character-preserving string `"50000.00"`, not a float that could lose precision or silently renormalize to `50000.0`. |
| 7 | **Datetimes are ISO-8601 with a literal `Z` suffix**, no fractional seconds when `microsecond == 0`, also produced by Pydantic's `mode="json"` | `+00:00` vs. `Z` are the same instant but different bytes. Every timestamp in the protocol is constructed with `.replace(microsecond=0)` specifically so this never needs a fractional-second rule. |
| 8 | **`None` serializes to `null`, never omitted** | Presence ambiguity — `"expires_at":null` must appear in the bytes; a field silently missing is not the same signed claim as a field explicitly nulled. |

## Worked example

Input (a `dict`, as if already dumped from a model with `mode="json",
by_alias=True`):

```json
{"@context": "https://custos.protocol/v1", "amount": "50000.00", "whole": 500.0, "optional": null, "tags": ["zebra", "alpha"]}
```

Canonical bytes (`exclude=set()`):

```
{"@context":"https://custos.protocol/v1","amount":"50000.00","optional":null,"tags":["zebra","alpha"],"whole":500}
```

Note: `whole` lost its `.0`; `amount` kept every character of its string form
untouched; `tags` kept its input order (arrays are **never** sorted, only
object keys); `optional` is present as `null`; keys are alphabetical
(`@context` first).

## Conformance vectors

`vectors.json`'s `serialization` category (`K01`–`K05`) pins exactly these
rules with byte-exact hex payloads. `run_conformance.py` byte-diffs a mismatch
and reports the first differing offset with surrounding context — start there
if your implementation disagrees.
