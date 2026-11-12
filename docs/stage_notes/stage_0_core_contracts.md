**Network Sentinel, Stage 0 learning pack (core contracts and foundation).** This pack explains the real code in this folder. Read it with the files open next to it.

## 1. Code walkthrough

The data flows like this: the error classes are used by the contracts, the contracts are used by every other module, and the configuration is separate. The files are covered in that order.

**core/errors.py**

- **Purpose:** gives the project its own named errors, so a caller can write `except ContractError` and know exactly what went wrong. These nine classes are the only classes in the project.
- **Inputs / outputs:** none. A class is a name plus a family tree. `NetworkSentinelError` is the parent. `ContractError`, `ConfigError`, `IngestionError`, `ReportError` and `DatabaseError` are its children. `BrokenReferenceError`, `IncidentNotFound` and `InvalidStatusTransition` are children of `DatabaseError`.
- **Logic and example:** because `BrokenReferenceError` is a kind of `DatabaseError`, code that says `except DatabaseError` also catches it. A test checks this with `issubclass`.
- **Limitations:** the classes carry only a message, no error codes. Later stages decide how to show messages to a user.

**core/contracts.py**

- **Purpose:** the shared rulebook. Every other module must build events and alerts through this file, so an invalid or badly identified event can never enter the system.
- **Inputs / outputs:** plain values in (text, numbers, datetimes, dictionaries). Plain dictionaries out (events, alerts), plus text IDs and lists of problem sentences.

*Part A: constants.* `EVENT_KEYS` (15 names), `ALERT_KEYS` (13), `EVENT_CONTENT_KEYS` (the 11 names that describe what happened), the allowed values, and `ALLOWED_STATUS_TRANSITIONS`. One decision to notice: `CONTRACT_VERSION = 1.0` is a number, as the specification writes it.

*Part B: small yes/no helpers.* The one most worth understanding is:

```python
    return isinstance(value, int) and not isinstance(value, bool)
```

In Python `True` is secretly the number 1, so without the `not isinstance(value, bool)` part a port of `True` would pass as a valid whole number.

*Part C: time helpers.* `datetime_to_iso` always produces the same 32-character shape:

```python
    return utc_value.strftime(_ISO_FORMAT)
```

`_ISO_FORMAT` is `"%Y-%m-%dT%H:%M:%S.%f+00:00"`. Because every timestamp has the same width, text sorts in time order and two equal instants always give the same text. `datetime_to_iso` refuses a naive datetime (one with no timezone) because we would have to guess its timezone. `iso_to_datetime` accepts only that exact shape.

*Part D: `canonical_json`.* It turns a dictionary into one agreed piece of text:

```python
        return json.dumps(
            data,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
```

Sorted keys, no spaces, accents written as `\uXXXX`, and `None` written as `null`. Hashing needs identical text for identical data, and this function guarantees it.

*Part E: event IDs.* `make_event_id` adds the file name and the occurrence number to the 11 content values, then hashes:

```python
    id_content["source_file"] = source_file
    id_content["occurrence"] = occurrence
    full_hash = _hash_text(canonical_json(id_content))
    return "EVT-" + full_hash[:EVENT_ID_HEX_LENGTH]
```

Worked example. The first sample row (`2025-03-14T09:15:02,203.0.113.50,admin,failure,10.0.0.5,ssh` in `auth_sample.csv`, first time seen) becomes this text, which is exactly the text printed in the specification:

```
{"bytes_received":null,"bytes_sent":null,"destination_ip":"10.0.0.5","destination_port":null,"event_type":"authentication","occurrence":1,"protocol":null,"service":"ssh","source_file":"auth_sample.csv","source_ip":"203.0.113.50","status":"failure","timestamp":"2025-03-14T09:15:02.000000+00:00","username":"admin"}
```

Its SHA-256 hash starts `37f239749a51d00c...`, so the ID is `EVT-37f239749a51d00c`. If the same line appeared a second time in the same file it would be hashed with `"occurrence":2` and get `EVT-837cd6fc2a2a2201`. The same row in a file called `auth_copy.csv` gets `EVT-ea0703cf4a631694`. `source_row` and `raw_event` are never hashed, so adding blank lines at the top of a file does not change any ID.

*Part F: alert IDs.* `make_alert_id` hashes the rule, source address, time range and the supporting event IDs:

```python
        "event_ids": sorted(event_ids),  # sorted() makes a new list
```

`sorted()` returns a new list, so the caller's list is never reordered. This is why shuffled evidence gives the same alert ID, while one extra event gives a different one. Example: `["EVT-bbbbbbbbbbbbbbbb", "EVT-aaaaaaaaaaaaaaaa"]` and `["EVT-aaaaaaaaaaaaaaaa", "EVT-bbbbbbbbbbbbbbbb"]` both give `ALT-d4865f22a471cfa4` for the NET_PORT_SCAN example in the fixture.

*Part G: checking and building.* Many small private functions (`_check_core_event_fields`, `_check_optional_text`, `_check_evidence`, and so on) each add sentences to a list called `problems`. `_find_event_field_problems` and `_find_alert_field_problems` run them all. Two public functions use that list in different ways:

- `make_event` and `make_alert` raise one `ContractError` listing every problem, because bad data must not be built.
- `validate_event` and `validate_alert` return the list, because they inspect dictionaries that already exist. An empty list means valid. They report every missing key, and they only run the value checks once all keys exist.

`make_event` also does `fields["raw_event"] = dict(raw_event)`, which stores a copy so the caller cannot change the original CSV row later.

- **Limitations:**
  - The contracts cannot check that an event ID really matches its content, because the occurrence number is not stored in the event.
  - `validate_alert` cannot check the time-range rule (every referenced event lies between `time_start` and `time_end`), because it has no events. The detection tests in Stage 1B check that rule.
  - Evidence is stored as given, not deep-copied.
  - A 16-hex-character ID is 64 bits, so an accidental collision is possible in theory and extremely unlikely.
  - `source_row` must be 2 or more, because line 1 of a CSV file is the header.

**config/settings.py**

- **Purpose:** the one configuration dictionary (17 settings) with its defaults, and a checker.
- **Inputs / outputs:** `get_default_config()` takes nothing and returns a fresh dictionary. `validate_config(config)` takes a possibly partial dictionary and returns a complete, checked copy, or raises `ConfigError`.
- **Important lines:** the 10 MB limit is written as decimal bytes.

```python
    "volume_min_bytes": 10000000,  # 10 MB means 10,000,000 bytes (decimal), NOT 10,485,760
```

`get_default_config` makes a new empty `trusted_ips` list each time, because otherwise every copy would share one list and a change in one place would leak into the defaults.

- **Logic and example:** `validate_config({"auth_failed_threshold": 3})` starts from the defaults, copies the 3 over, then checks that every whole-number setting is a whole number above zero. `True` is refused, `5.5` is refused and `"5"` is refused. `volume_min_coverage` must be above 0 and at most 1 because it is a share. `trusted_ips` addresses are rewritten into normalised form, so `2001:DB8::1` becomes `2001:db8::1` and matches the `source_ip` of events.
- **Limitations:** an unknown key (for example a typo such as `auth_failed_treshold`) raises `ConfigError` instead of being ignored. The specification does not say this; it was added so that a typo cannot silently leave a threshold at its default. Settings are checked one at a time, so relationships between settings are not checked.

**data/sample/auth_sample.csv and network_sample.csv**

- **Purpose:** synthetic data with known outcomes, for the ingestion tests and the integration tests. Every address is from a documentation range (203.0.113.0/24, 198.51.100.0/24, 192.0.2.0/24) or a private range (10.0.0.0/8).
- **Contents:** `auth_sample.csv` has 20 rows; `network_sample.csv` has 52. They contain:
  - a login burst from 203.0.113.50: 8 failures with 4 usernames, then one success 42 seconds after the last failure;
  - a port scan by the same address: 18 ports in 18 seconds, 17 of them rejected;
  - a client at 10.0.0.31 with exactly 20 rejections in 95 seconds, all to the same address and port;
  - a host at 10.0.0.40 with 8 ordinary 5-minute buckets and one of 12,000,000 bytes;
  - benign rows: a forgetful user, 4 failures from 198.51.100.77 (one below the threshold), a busy web client, and an ICMP row with no bytes.
- **Limitations:** the files have no malformed rows. additional malformed cases are covered by the ingestion fixtures. The expected outcomes were worked out by hand from the rules in the specification, because detection does not exist yet; Stage 1B and Stage 4 will confirm them.

**tests/fixtures/expected_results.json**

- **Purpose:** the fixed values the tests compare against: five golden event IDs, one golden fingerprint, three golden alert IDs, the 10,000,000-byte value, the sample row counts, and the five alerts the sample files should produce (four base alerts and one correlated alert).
- **How the golden values were produced:** the canonical texts were typed by hand from the specification (not generated by the code), hashed with the command-line tool `sha256sum`, and only then compared with what the project code produced. They agreed.
- **Limitations:** if the contract ever changes on purpose (through the H.6 process), these values must be recomputed and the change explained.

**tests/test_contracts.py**

- **Purpose:** 118 tests for everything above. The key idea: a test must be able to fail. Every ID test compares with a value stored in the fixture, never with a fresh calculation by the same code.
- **How it checks bad input:** the helper `check_every_bad_value_is_rejected` takes one valid set of arguments, replaces one field at a time with a bad value, and fails if `ContractError` is not raised.
- **Limitations:** it tests the contracts, the configuration, the sample file shapes and the fixture. It does not test ingestion, detection or storage, which belong to other stages.

## 2. Key concepts introduced in this stage

- **Contract:** an agreed shape for data that every module follows, so modules can be built separately and still fit together.
- **Factory function:** a function that builds a valid object and refuses to build an invalid one (`make_event`, `make_alert`).
- **Validation that raises versus validation that reports:** `make_*` raises an error, `validate_*` returns a list of problems.
- **Timezone-aware datetime and UTC:** a datetime that knows its offset from UTC. A naive datetime does not, so two naive times cannot be compared safely.
- **Canonical form:** one agreed way to write the same data, so equal data always gives equal text.
- **Hash (SHA-256):** a fixed-size fingerprint of some text. The same text always gives the same fingerprint, and a tiny change gives a completely different one.
- **Deterministic ID:** an ID computed from the content, so the same input always produces the same ID (no random numbers or UUIDs).
- **Occurrence counter:** a count of identical rows seen so far in one file, so genuine repeats keep different IDs.
- **None versus empty text versus 0:** three different things. A missing value is always `None`, and `0` is a real value.
- **`bool` is a kind of `int` in Python:** a surprising rule that the code has to guard against.
- **Golden values:** fixed expected results stored in a file, so a later change cannot quietly alter IDs.
- **Why `get_default_config` makes a copy:** a list inside a dictionary is shared unless you build a new one.

## 3. Questions for the reader

1. Why does the event ID include the file name and an occurrence number, and what does each one protect against?
2. Why is canonical JSON safer than joining the fields with `|`? Give an example of two different events that the `|` method could confuse.
3. Why does `make_alert_id` sort a copy of the event IDs, and why must it not sort the caller's own list?
4. Why must every timestamp be timezone-aware UTC, and why is the text format always 32 characters wide?
5. What is the difference between `make_event` and `validate_event`, and when would you use each?
6. Why are the golden hash values stored in `expected_results.json` instead of being calculated inside the test?
7. Why are `source_row` and `raw_event` left out of the event ID? What would go wrong if they were included?
8. Why is the traffic minimum written as `10000000` and not `10485760`? Which sentence in the specification fixes this?
9. **Edge case:** a file contains the same failed-login line three times. What occurrence numbers do the three events get, and what happens to their IDs if the same file is uploaded again?
10. **Edge case:** the same file is uploaded again under the new name `auth_copy.csv`. Are the IDs the same? What will the system do about it in Stage 1A?
11. **Edge case:** an alert is built with `event_ids` of `["EVT-a", "EVT-a"]`. What happens, and why does the contract treat this as an error?
12. **Edge case:** a username is the empty string `""` instead of `None`. What does `make_event` do, and why is `None` safer?
13. **Edge case:** someone passes `True` as a destination port. Why is that rejected even though Python treats `True` as 1?

## 4. A small practical modification exercise

About 30 minutes. Do this on a **scratch copy** of the project, never on the real one: the incident ID format is part of the frozen contract, so a real change would need the H.6 change process and a new `CONTRACT_VERSION`.

1. Copy the project folder and open the copy.
2. In `core/contracts.py`, find the function `format_incident_id`. Change the padding so incident 7 becomes `INC-00007` (five digits). The padding is the `.zfill(4)`.
3. Run `python -m pytest tests/test_contracts.py -v`. Read the failure message for `test_format_incident_id`: it shows what the test expected and what the function returned.
4. In `tests/test_contracts.py`, edit the test `test_format_incident_id` so it expects `INC-00007`, `INC-00000`, `INC-01234` and `INC-12345`. Then add one assertion of your own, for example for incident 99999.
5. Run the tests again. **Expected result:** all 118 tests pass in the working copy.
6. Write two sentences answering: which other modules would have to change if this were a real change, and why is it listed in FS.4 as a contract that needs the H.6 process?
7. Throw the scratch copy away.

## 5. Concepts to study before moving to the next stage

- The `csv` module: `csv.reader` and `csv.DictReader`, what happens with short and long rows, and how line numbers map to row numbers (the header is line 1).
- Text and bytes: what UTF-8 is, what a byte order mark is, and how `bytes.decode("utf-8")` fails on bad input.
- `datetime.strptime` and `datetime.fromisoformat`, timezone offsets and how to convert them to UTC.
- The `ipaddress` module: `ip_address`, how addresses are normalised, and IPv6 compression.
- Dictionary tallies: counting how many times a key has been seen, as used for the occurrence number.
- `pytest` basics: `pytest.raises`, `tmp_path`, and how to build small test files on the fly.
- Revisit `json.dumps` options (`sort_keys`, `separators`, `ensure_ascii`) and be able to say what each one does to the output.
