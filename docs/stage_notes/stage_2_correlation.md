**Network Sentinel, learning pack for Stage 2A (correlation and the analysis engine).** Read it with the real files open next to it. It follows FS.3.4, FS.4 (`run_analysis`, `correlate_alerts`), R2.5 and R2.7.

## 1. Code walkthrough

The data flows like this: `run_analysis` checks the configuration, calls the four rule functions (Stage 1B), passes the base alerts to `correlate_alerts`, then sorts and returns everything. Every correlated alert is built by `make_alert`, so its ID follows the same deterministic rule as every other alert.

**correlation/correlator.py**

- **Purpose:** `correlate_alerts(alerts, events, config)` returns new CORR_AUTH_NET alerts.
- **Logic:** for every authentication alert and every network alert with the SAME non-trusted source address, work out the time gap (0 if the ranges overlap). Link them only if the gap is at most `correlation_window_seconds` (inclusive). Close timestamps alone never link alerts. `event_ids` is the union without duplicates, in time order. `destination_match` is true if the two alerts' events share a destination address; it only raises confidence (medium to high) and never creates a link. Severity is high, or critical if the login alert has `followed_by_success` true.
- **Merge rule (see the unresolved questions):** two pairs that cover exactly the same events would get the same alert ID, so they are folded into one alert listing all linked base alert IDs.
- **Limitations:** only `source_ip` links alerts, so one shared address can make a false link.

- **Same-evidence rule (a design question for the architecture/dashboard modules):** a 20-port scan is also 20 rejected connections, so one login burst can pair with both a NET_PORT_SCAN alert and a NET_REPEATED_REJECTS alert made of the same events. Both pairs would get the same alert ID (FS.3.2), and `INSERT OR IGNORE` would silently keep only one. `_merge_same_evidence` therefore keeps ONE correlated alert and lists every linked base alert in `linked_alert_ids`. Nothing is lost: the two pairs have identical event sets, so identical time ranges, gap and destination match.

**detection/engine.py**

- **Purpose:** `run_analysis(events, config)` checks the configuration, runs the four rules and the correlator, gives every alert the same `detected_at`, sorts by `time_start` then `rule_id`, and returns `alerts`, `base_alert_count`, `correlated_alert_count`, `notes`, `events_analysed`, `events_ignored_trusted`, `analysed_at`.
- **Why it has its own config check:** detection may not import `config/settings.py`, so `_check_detection_config` raises `ConfigError` itself.

**Integration example** (normalised events -> detection -> correlation -> storage):

```python
from config.settings import get_default_config, validate_config
from detection.engine import run_analysis
from storage.database import save_alerts            # the storage/reporting modules, not built here

config = validate_config(get_default_config())
events = combined["events"]                          # from combine_ingestion_results (the ingestion module)
result = run_analysis(events, config)                # rules, then correlation
for note in result["notes"]:
    print(note)                                      # skipped rules are always shown
summary = save_alerts(db_path, result["alerts"], events, result["alerts"])
```

The dashboard passes the full alert list as both `alerts` (or the user's selection) and `available_alerts`, so storage can find the base alerts of a correlated alert. A test (`test_alerts_are_ready_for_storage_save_alerts_checks`) checks every alert is valid, every event ID is in the event list, and every linked base alert is in the alert list.

**Integration example** (normalised events -> detection -> correlation -> storage):

```python
from config.settings import get_default_config, validate_config
from detection.engine import run_analysis
from storage.database import save_alerts            # the storage/reporting modules, not built here

config = validate_config(get_default_config())
events = combined["events"]                          # from combine_ingestion_results (the ingestion module)
result = run_analysis(events, config)                # rules, then correlation
for note in result["notes"]:
    print(note)                                      # skipped rules are always shown
summary = save_alerts(db_path, result["alerts"], events, result["alerts"])
```

`test_alerts_are_ready_for_storage_save_alerts_checks` checks every alert is valid, every event ID is in the event list, and every linked base alert is in the alert list.

**Why an alert is not proof:** a rule recognises a pattern, and harmless things make the same pattern (a forgotten password, a vulnerability scanner, a backup, an office router). So alert texts say "possible" or "recorded", never "compromised", "breached", "attacker" or "confirmed", and every alert lists its limitations.

## 2. Key concepts introduced in this stage

- Correlation by one shared key (source address) and a time gap; close timestamps alone are not evidence.
- The gap between two time ranges (zero when they overlap) and an inclusive limit.
- The union of two lists without duplicates, kept in time order.
- Why a destination match only raises confidence and never creates a link.
- An entry-point function that checks its input, runs the parts in order, and reports what it skipped.
- Deterministic output: the same events always give the same alert IDs.

## 3. Questions for the reader

1. **What exactly links an authentication alert and a network alert?** Same non-empty, non-trusted source address, and time ranges that overlap or are at most `correlation_window_seconds` apart (inclusive).
2. **Why does a matching destination address not create a link?** It only raises confidence from medium to high.
3. **Edge case: the same address, but the alerts are two hours apart. What happens?** The gap is above 900 seconds, so there is no correlated alert.
4. **Edge case: the gap is exactly 900 seconds, then 901. What happens?** 900 links (inclusive), 901 does not.
5. **When is a correlated alert critical?** When the linked authentication alert has `followed_by_success` true; otherwise high.
6. **Why is `event_ids` a union without duplicates, and in time order?** The original evidence is preserved with nothing repeated, and every alert keeps its event IDs in time order (FS.3.2).
7. **Edge case: two network alerts are made of the same events. What happens?** Both pairs would have one alert ID, so the correlator keeps one alert listing both base alerts.
8. **What does `run_analysis` do with a bad configuration?** It raises `ConfigError` before any rule runs (detection may not import `config/settings.py`, so it checks the settings itself).
9. **What does `run_analysis` do with junk or repeated events?** It skips them and adds a note; nothing crashes.
10. **Why is the trusted-address check made in every rule and in the correlator?** Each module must work alone with hand-made data.

## 4. A small practical modification exercise

**Time: about 30 minutes.** In `tests/test_correlation.py`, copy `test_correlation_gap_boundary_is_inclusive` and add a case for `correlation_window_seconds=60` (pass it through `correlate(events, correlation_window_seconds=60)`): a scan starting 80 seconds after the login burst ends at 20 seconds is exactly 60 s apart and must link; one second later must not. Run `python -m pytest tests/test_correlation.py -v`. Expected result: both cases pass without changing any source file. Explain why the gap uses `timedelta` and not whole seconds.

## 5. Concepts to study before moving to the next stage

- How a dictionary is used to find duplicates (`alerts_by_id`).
- Set intersection (shared destination addresses).
- Foreign keys and transactions, which the storage stage uses to save a correlated alert with its base alerts.
- How Streamlit session state holds `analysis` (Stage 3 and 4).
