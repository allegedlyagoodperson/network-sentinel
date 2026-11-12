**Network Sentinel, Stage 1A learning pack (CSV ingestion).** Read this with `ingestion/validators.py`, `ingestion/csv_ingest.py` and `tests/test_ingestion.py` open next to it.

## 1. Code walkthrough

The data flows like this: the **bytes** of a CSV file arrive, `ingest_file` checks the file as a whole, splits it into lines, reads the header, then handles each row with the small checkers in `validators.py`. Each good row becomes an event through the Stage 0 function `make_event`. `combine_ingestion_results` then merges several files. The files are covered in that order: first the small checkers, then the file reader, then the combiner, then the tests.

**ingestion/validators.py**

- **Purpose:** one small function per kind of value. Each checks a single cell and raises `ValueError` with a short message when the cell is bad. This file never reads files and never builds events.
- **Inputs / outputs:** text in (a cell), a clean Python value out (a UTC `datetime`, a normalised address `str`, an `int`, a status word, trimmed text), or a `ValueError`.
- **Important functions:** `parse_timestamp`, `parse_ip_address`, `parse_port`, `parse_optional_non_negative_int`, `normalise_status`, `clean_text_value`, `check_columns`.

*Logic and worked example: `parse_timestamp`.* We read the text by hand, in three steps (date, time, zone), instead of calling `datetime.fromisoformat`, because newer Python versions accept many extra formats and the specification (D.2) lists only a few.

```python
    if cleaned[10] != "T" and cleaned[10] != " ":
        raise ValueError("date and time must be separated by T or a space")
    year, month, day = _parse_date_part(cleaned[0:10])
    hour, minute, second = _parse_time_part(cleaned[11:19])
    microsecond, zone_text = _split_fraction_and_zone(cleaned[19:])
```

For `"2025-03-14T10:15:02+01:00"`: the date part is `2025-03-14`, the time part is `10:15:02`, the tail is `+01:00`, so the zone is plus one hour. Python builds `10:15:02+01:00` and `astimezone(timezone.utc)` converts it to `09:15:02 UTC`. A text such as `14/03/2025 09:15:02` fails at `_parse_date_part` (position 4 is not a `-`), so it is rejected as ambiguous.

*The digit trap.* Every digit check uses our own helper, not `str.isdigit()`:

```python
_DIGITS = "0123456789"  # ASCII digits only: str.isdigit() would also accept other scripts
```

`"８０".isdigit()` is `True` in Python (full-width digits), but `int("８０")` also works, so a hostile or odd cell could slip through as a "number". Our helper accepts only the ten ASCII digits.

*`parse_ip_address`.* It calls `ipaddress.ip_address`, which also normalises: `2001:DB8:0:0:0:0:0:1` becomes `2001:db8::1`. One extra rule: an address with `%` (a "zone suffix" such as `fe80::1%eth0`) is refused, because Python would accept almost any text after the `%`, and that text could then travel into the address field of an event.

*`parse_port` and `parse_optional_non_negative_int`.* Only the digits 0-9. Leading zeros are dropped *before* converting, so a 5000-digit cell is refused cheaply instead of being converted. Byte counts above 9223372036854775807 (the biggest whole number SQLite can store) are refused, so a hostile number cannot crash the storage stage later.

*`normalise_status`.* Two dictionaries map the words of Section C.1 to the four allowed values: `"drop"` becomes `rejected` for network logs; `"denied"` becomes `failure` for authentication logs but `rejected` for network logs. The same word can mean different things in different logs, which is why `log_type` is a parameter.

- **Limitations:** timestamps with more than six fractional digits are rejected, not rounded (a limit of our reading of D.2; see the questions below). `clean_text_value` uses the specification's definition of a control character (codes below 32, and 127-159); invisible Unicode characters such as a zero-width space are not control characters by that definition and are kept.

**ingestion/csv_ingest.py**

- **Purpose:** turn the bytes of one untrusted file into events and a list of rejected rows (`ingest_file`), and merge several results (`combine_ingestion_results`).
- **Inputs / outputs:** `ingest_file(file_bytes, file_name, log_type, config)` returns a dictionary with `file_name`, `log_type`, `events`, `rejected_rows`, `summary`. A problem with the *whole file* raises `IngestionError` and nothing is returned.
- **Important functions:** `_check_file_name`, `_check_file_bytes`, `_decode_text`, `_split_into_lines`, `_parse_line`, `_check_header`, `_convert_row`, `_count_occurrence`, `_build_event`, `_process_row`, `_read_data_rows`, `ingest_file`; then `_merge_events_and_drop_repeats`, `_find_overlap_warnings`, `combine_ingestion_results`.

*Logic of `ingest_file`, in order.* (1) Read the three settings from `config` (`max_upload_mb`, `max_rows_per_file`, `assume_utc`); this module never imports `config/settings.py` (Section 0), it only receives the dictionary. (2) File-level checks: log type, file name (`.csv`, no folder path), size, empty, valid UTF-8, no NUL bytes. (3) Split into lines and find the header. (4) Check the header: duplicate names and missing required columns stop the file; unknown extra columns only add a warning. (5) Process each data row. (6) Build the summary.

*Why every line is parsed on its own.* This is the most important design choice in the file:

```python
    try:
        parsed_rows = list(csv.reader([line]))
    except csv.Error:
        return line.split(",")
```

If we gave the `csv` module the whole file, one stray quote mark (`"unterminated`) would make it read to the end of the file as a single cell and silently swallow every later row. By giving it one physical line at a time, a bad quote can damage only its own row. A test (`test_a_stray_quote_damages_only_its_own_row`) checks that the row after the damaged one survives. The price: a quoted cell that contains a line break is not supported (it becomes two bad rows). Log files do not have these.

*Row numbers.* `_split_into_lines` splits only on `\r\n`, `\r` and `\n` and a line's number is its position plus one, so the header is line 1 and the first data row is line 2, exactly as a spreadsheet shows it. Blank lines keep their place in the count, so the numbers always match what the user sees.

*How a row is checked.* `_convert_row` walks the columns in the order of the D.3 and D.4 tables and `_convert_cell` stops at the first problem, which is exactly the rule of D.5 ("rejected for the first problem found"):

```python
    if text.strip() == "":
        if column_name in REQUIRED_COLUMNS_BY_LOG_TYPE[log_type]:
            raise ValueError("missing_required_value:" + column_name)
        return None
    try:
        return _convert_non_empty_cell(column_name, text, log_type, assume_utc)
    except ValueError as error:
        raise ValueError(_make_rejection_reason(column_name, error)) from error
```

An empty *optional* cell becomes `None` (never an empty string, Section 0). A failed validator becomes one of the fixed reason texts, for example `invalid_ip:source_ip`. The `too_many_columns` check comes before all of these, because a row with extra cells cannot be read reliably.

*Worked example.* The row `2025-03-14T09:15:02,999.1.1.1,admin,maybe,,` on line 7 of an authentication file: the timestamp is fine, the source IP fails, so the walk stops and the result is the rejected row `{"source_file": "x.csv", "source_row": 7, "reason": "invalid_ip:source_ip", "raw_row": {...}}`. The bad status is never even looked at. The other rows continue.

*Event IDs and the occurrence tally.* Ingestion never builds an ID. It counts how many times the same content has appeared in this file, then asks `make_event` to do the rest:

```python
    seen_before = tally.get(tally_key, 0)
    tally[tally_key] = seen_before + 1
    return seen_before + 1
```

The tally key is the canonical JSON text of the 11 content keys (`canonical_json` from `core/contracts.py`). Three identical lines therefore get occurrence 1, 2, 3 and three different IDs. A rejected row never reaches the tally, so it does not use up a number. The tally is a new empty dictionary for every file. Because the file name is part of the ID (decision D2), the same rows in a renamed file get different IDs, and `combine_ingestion_results` warns about the overlap instead of merging.

*`combine_ingestion_results`.* It (1) keeps the first copy of each `event_id` (the only way the same ID can appear twice is the same file name and rows added twice), counts the rest as `duplicates_removed` and adds a warning naming the file; (2) sorts events by timestamp, then file name, then row number; (3) compares every pair of *differently named* files with `make_content_fingerprint` and warns if they share events; nothing is removed for overlap. It returns exactly the keys `events`, `rejected_rows`, `summaries`, `duplicates_removed`, `overlap_warnings`. Section E.5 lists no errors for this function, so it raises no project exception: if someone passes something that is not a list of `ingest_file` results, Python's own `TypeError` or `KeyError` appears, which is the right signal for a programming mistake.

- **The summary warning for a mostly-rejected file** is exactly the text `high_rejection_rate` (the name used in D.1); the numbers are already in the summary (`rows_rejected`, `rows_read`).
- **Limitations:** the whole file is held in memory (the 10 MB limit keeps that small). A file added twice has its events de-duplicated but its rejected rows are listed twice. `1 MB` means 1,000,000 bytes (decimal), the same convention as the 10 MB of `volume_min_bytes`. The row limit counts data rows excluding blank lines.

**tests/test_ingestion.py and tests/fixtures/ingestion_\***

- **Purpose:** prove the module follows the *specification*, not just my own assumptions. Expected values come from Section D (reason texts), Section C.1 (status words), the Stage 0 golden event ID `EVT-37f239749a51d00c` (the sample file must reproduce it), and an independent hash worked out with `hashlib` and `json` inside the test (`hand_made_event_id`).
- **Logic:** each rejected-row reason has its own small fixture file with a good line 2, a bad line 3 and a good line 4, so the test can check that only line 3 was rejected and that `rows_read = events_accepted + rows_rejected`.
- **Limitations:** the tests check behaviour on synthetic data only. They show the code implements the rules we wrote, not that it handles every real-world export.

## 2. Key concepts introduced in this stage

- **Untrusted input:** a file is data from outside. We never assume it is well formed, never evaluate it (a username starting with `=` is just text) and never let it crash the program.
- **File-level versus row-level errors:** a problem with the whole file (wrong type, no header) raises an exception and accepts nothing; a problem with one row rejects only that row and carries on.
- **Normalisation:** many spellings (`FAILED`, `Fail`, `denied`) become one value (`failure`), so detection can compare values with `==`.
- **Validation order:** with several problems in one row, the *first* one in a fixed column order is reported, so results are predictable and testable.
- **`None` for missing:** an empty cell becomes `None`, not `""` or `0` (Section 0), and `None`, `""` and `0` give different event IDs.
- **Deterministic IDs and occurrence:** the same input always gives the same ID; repeated rows are kept apart by a per-file counter.
- **UTC and timezone-aware datetimes:** all times are converted to UTC so that events from different files can be compared and sorted.
- **Defence in depth against hostile data:** ASCII-only digit checks, length limits, control-character checks, no scope IDs in addresses, numbers capped to what SQLite can store.
- **Boundary testing:** exactly at the limit is accepted, one over is rejected (100,000 and 100,001 rows; 1,000,000 and 1,000,001 bytes).
- **Dependency discipline:** ingestion imports only `core` and the standard library; no Streamlit, SQLite or `config/settings.py`.

## 3. Questions for the reader

1. **Why does `ingest_file` raise an exception for a file with no `username` column, but only *reject a row* that has an empty username?** A missing column means every row would fail, so the file cannot be read at all. An empty username affects one row; the other rows are fine and should still be analysed.
2. **A row has a bad IP address and a bad status. Which reason is reported, and why?** `invalid_ip:source_ip`. Section D.5 says a row is rejected for the first problem found, checking the columns in the order of the tables, and `source_ip` comes before `status`.
3. **Why is the file name part of the event ID?** (Decision D2.) So that identical events in two differently named files are never silently merged: a second sensor could genuinely have seen the same thing. The price is that overlapping exports are counted twice, so we warn about overlap instead.
4. **What is the occurrence number and what happens without it?** It counts identical rows within one file (1, 2, 3...). Without it, three identical failed-login lines would have one ID and two of them would look like duplicates, so the burst would be counted as 1 failure instead of 3.
5. **Why does uploading the same file twice give identical IDs, but uploading a renamed copy does not?** The ID is a hash of the content, the file name and the occurrence. Same file: all three are equal. Renamed copy: the file name differs, so the hash differs.
6. **Why not use `datetime.fromisoformat` to read timestamps?** It accepts more formats than the specification allows, and the accepted set changes between Python versions. Reading the pieces by hand makes the rules exact and the same on every machine.
7. **Edge case: what happens if the file has exactly 100,000 data rows? 100,001?** 100,000 is accepted; 100,001 raises `IngestionError` for the whole file (decision D6). Blank lines do not count as data rows.
8. **Edge case: a timestamp has no timezone and `assume_utc` is `False`. What happens?** The row is rejected as `invalid_timestamp`. With `assume_utc` `True` (the default) it is treated as UTC (decision D1).
9. **Edge case: a username is `=cmd|' /C calc'!A0`. What happens?** It is accepted and stored as plain text. Nothing is ever evaluated. (A future CSV *export* would have to prefix such values with an apostrophe; see D.1.)
10. **Edge case: a row has an opening quote mark that is never closed. What happens to the rest of the file?** Only that row is affected (usually rejected as `missing_required_value:...` because the commas were swallowed into one cell). Each line is parsed separately, so later rows are safe.
11. **Why does `parse_port` remove leading zeros before converting?** So a hostile cell of thousands of digits is refused after a cheap length check instead of making Python convert a huge number.
12. **Why does `combine_ingestion_results` warn about overlap instead of removing the overlapping events?** Because we cannot know whether two files are overlapping exports (duplicates) or two genuine sources; the analyst decides. Silent merging could hide a real event.
13. **What does "1 MB" mean for `max_upload_mb`, and where does the specification leave room for doubt?** We use 1,000,000 bytes (decimal), the same convention the specification states for the 10 MB of `volume_min_bytes`. For the upload limit it does not say which convention to use, so this is listed as an open question. A file of exactly 1,000,000 bytes is accepted and 1,000,001 is refused.
14. **Why does ingestion not import `config/settings.py`?** Section 0: pipeline modules receive the configuration as a parameter. This makes `ingest_file` testable on its own with a hand-made dictionary and keeps the dependency arrows pointing one way.

## 4. A small practical modification exercise

This takes about 30 minutes.

**Task:** network logs from a different firewall use the status word `timeout`. Make it count as `rejected`.

1. Open `ingestion/validators.py` and find the dictionary `NETWORK_STATUS_WORDS`. Add one entry: `"timeout": "rejected",`.
2. Open `tests/test_ingestion.py`, find `test_status_words_network`, and add `"timeout"` to the `rejected_words` list.
3. Add a new test below it that ingests one network row with the status `Timeout` (use `ingest_text(NETWORK_HEADER + "\n2025-03-14T09:15:02,203.0.113.4,10.0.0.5,80,TCP,Timeout,0,0\n", NETWORK)`) and asserts that the event's `status` is `"rejected"` and that there are no rejected rows.
4. Run `python -m pytest tests/test_ingestion.py` from the project root.

**Expected result:** the new test passes, and `"timeout"` for an *authentication* file is still rejected as `invalid_status` (add one line to check that too). Then answer: why is this change allowed in `validators.py` but a change to the list of allowed statuses in `core/contracts.py` is not (hint: Section H.6)?

## 5. Concepts to study before moving to the next stage

Stage 1B (detection) receives the list of events that this stage produces, so study:

- **Grouping with dictionaries:** building `{source_ip: [events]}` by looping and using `dictionary.get(key, default)`, as `_count_occurrence` does for the tally.
- **Sorting and time order:** why events must be sorted by `timestamp` before a sliding window can work (`combine_ingestion_results` already does this).
- **`datetime` and `timedelta` arithmetic:** subtracting two aware datetimes gives a `timedelta`; `.total_seconds()` gives a number you can compare with a threshold.
- **The sliding-window idea with two position markers** (`find_bursts`, Section C.6) and inclusive boundaries (exactly the threshold triggers).
- **Sets and `len(set(...))`** for counting distinct values, such as distinct ports.
- **The median** (sort, then middle value or average of the two middle values) for `NET_HIGH_VOLUME`.
- **How to read the event dictionary:** the 15 keys of Section C.1, and why detection must skip an event with a `None` field it needs instead of failing.
