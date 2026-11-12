**Network Sentinel, learning pack for Stage 1B (detection rules).** Read it with the real files open next to it. Every rule follows the frozen specification (FS.3.3, R1.3, R1.4, R2.2, R2.3).

## 1. Code walkthrough

The data flows like this: normalised events (made by ingestion with `make_event`) are cleaned and sorted by `_clean_events`, grouped by the rule, searched for bursts by `find_bursts`, and turned into alerts by `make_alert` from Stage 0. Every alert ID comes from `make_alert`; no rule builds an ID itself.

**detection/windowing.py**

- **Purpose:** `find_bursts`, the shared sliding-window helper, plus small private helpers used by every rule (clean the event list, read the trusted addresses, plural text).
- **Inputs / outputs:** `find_bursts(timestamps, values, threshold, window_seconds)` takes a sorted list of timezone-aware times and returns a list of `(first_index, last_index)` pairs, both inclusive.
- **Important functions:** `find_bursts`, `_merge_ranges`, `_clean_events`, `_get_trusted_ip_set`.
- **Logic and worked example:** every event is treated as the right end of a window; the left marker moves forward until the window is at most `window_seconds` long. If the window holds at least `threshold` events (or distinct values) it triggers. Overlapping triggering windows are merged, so one long attack is one burst.

```python
while timestamps[right_index] - timestamps[left_index] > window_length:
```

  This line is the inclusive boundary: a gap of exactly 300 s is NOT greater than 300 s, so both events stay in the window. Example: five failures 10 s apart, threshold 5 -> `[(0, 4)]`; threshold 6 -> `[]`.
- **Limitations:** the caller must sort the times (the rules do). A burst can be much longer than the window, because it is the union of overlapping windows.

**detection/auth_rules.py** (rule AUTH_BRUTE_FORCE)

- **Purpose:** find bursts of failed logins from one source address, then link successes from that address.
- **Inputs / outputs:** `detect_failed_logins(events, config) -> (alerts, notes)`; notes is always empty.
- **Important functions:** `_group_auth_events`, `_find_linked_successes`, `_summarise_burst`, `_build_evidence`, `_build_alert`.
- **Logic:** failures are grouped by address and passed to `find_bursts`. For each burst, T is the time of the last failure. A success is linked only if it is from the same address and the time from T to the success is more than 0 and at most `auth_success_after_failure_seconds`:

```python
if gap > timedelta(0) and gap <= longest_gap:
```

  `gap` is a `timedelta`, so fractions of a second are exact. Strictly more than 0 means a success at the same timestamp is not linked (a log with one-second resolution cannot show which came first). At most the window means exactly 300 s is linked and 300.5 s is not.
- **Worked example:** 6 failures for `admin` at 0 to 5 s and a success for `admin` at 35 s. Alert: 7 event IDs, `time_end` is the success time, severity high, confidence low (one username, fewer than 10 failures). A success never changes confidence.
- **All successes are kept:** `event_ids` holds every linked success, `success_event_count` counts every one, and only the detail list `success_events` stops at 10 (`MAX_DETAILED_SUCCESS_EVENTS`). With 15 linked successes: count 15, detail length 10, `success_events_not_detailed` 5.
- **Limitations:** a mistyped password followed by the right one looks the same; many people behind one router look like one source; failures slower than the window are missed; an event without a username is skipped.

**detection/network_rules.py** (three rules)

- **NET_PORT_SCAN:** events grouped by (source, destination); `find_bursts` is called with the ports as `values`, so it counts distinct ports. Severity medium, high at 3 x the threshold (45 ports). Confidence high if at least 70 percent of attempts were rejected, low if at least 70 percent were allowed, otherwise medium. Whole-number arithmetic (`rejected * 10 >= total * 7`) avoids rounding surprises. Example: 18 ports, 17 of 18 rejected -> medium severity, high confidence.
- **NET_REPEATED_REJECTS:** rejected events grouped by source. Severity low, medium at 3 x the threshold. Confidence low if every rejection hit one address and one port (often a misconfigured client).
- **NET_HIGH_VOLUME:** per source address only. Buckets line up with the clock: `(whole_seconds // window) * window`, so 09:17:42 and 09:19:59 are both in the 09:15:00 bucket. Zero-byte buckets are discarded. A source needs at least 6 active buckets or it is skipped (one summary note, at most 10 addresses). The baseline is that source's own median, calculated by hand in `_median`. A bucket triggers if it is at least 10,000,000 bytes AND at least 5 x the median (both inclusive). Example: totals 1, 1, 1, 1, 1, 10 million -> median 1,000,000, the 10,000,000 bucket triggers. Severity medium, confidence low (fixed).
- **Limitations:** a nightly backup is a known false positive; a source that is always busy never triggers; a new machine with fewer than 6 active buckets is never checked.

**Why an alert is not proof:** a rule recognises a pattern, and harmless things make the same pattern (a forgotten password, a vulnerability scanner, a backup, an office router). So alert texts say "possible" or "recorded", never "compromised", "breached", "attacker" or "confirmed", and every alert lists its limitations.

## 2. Key concepts introduced in this stage

- A sliding window with two markers, and why overlapping windows are merged into one burst.
- Inclusive thresholds and boundaries ("exactly" triggers) and why `timedelta` is used for exact comparisons.
- Severity versus confidence: how bad it would be if real, versus how strongly the evidence supports it.
- A per-source baseline and the median (why a median resists one huge value).
- Clock-aligned buckets using whole-number division.
- Skipping bad input instead of crashing (FS.3.3), and why every rule sorts its own copy of the events.
- Labelled test data and the TP / FP / FN table of I.4 (`test_labelled_datasets_table_of_tp_fp_fn_per_rule`, run with `-s` to see it).

## 3. Questions for the reader

1. **Why is a success after failures high severity but not high confidence?** Severity asks how serious it would be if real; confidence asks how strongly the data supports it. A person who mistyped a password and then got it right produces the same pattern, so a success never raises confidence.
2. **Which successes are linked to a failure burst?** Same source address, strictly after the last failure, and at most `auth_success_after_failure_seconds` later (default 300, inclusive).
3. **Edge case: a success has exactly the same timestamp as the last failure. What happens?** It is not linked, because with one-second logs we cannot tell which came first.
4. **Edge case: a success arrives 300 seconds, then 300.5 seconds, after the last failure. What happens?** 300 is linked (inclusive upper bound); 300.5 is not.
5. **Why does an alert with 15 linked successes show only 10 in `success_events`?** Ten is a display limit only. `event_ids`, `success_event_count` and `time_end` use all 15; `success_events_not_detailed` is 5.
6. **Why is each machine compared only with itself in NET_HIGH_VOLUME?** A busy server would hide a quiet laptop's spike, and a quiet laptop would make the server look suspicious.
7. **Edge case: a source has only five active buckets. What happens?** It is skipped and one summary note names it (a false negative we announce).
8. **Why the median and not the average?** One huge bucket drags an average upwards and hides itself.
9. **How does `find_bursts` avoid hundreds of alerts for one long attack?** It merges triggering windows that overlap.
10. **Edge case: an authentication event has no username, or the same `event_id` appears twice. What happens?** The event without a username is skipped (the confidence rule needs it); a repeated `event_id` is kept once. Nothing crashes.
11. **Why did the labelled table show one false negative and one false positive?** `auth_slow_attack` spreads five failures over 20 minutes (beyond a 300 s window); `net_nightly_backup` is a large legitimate transfer that volume alone cannot tell from an attack.
12. **Why do scores on our own datasets not measure real-world detection?** We wrote both the attacks and the labels, so they only show the code does what we meant (I.4).

## 4. A small practical modification exercise

**Time: about 30 minutes.** In `detection/auth_rules.py`, change `_decide_confidence` so that exactly 2 distinct usernames with at least `2 * threshold` failures gives `"high"`. Edit `test_auth_confidence_rubric_for_several_usernames` in `tests/test_detection.py` to add a case with 10 failures and 2 usernames expecting `"high"`. Run `python -m pytest tests/test_detection.py -v`. Expected result: your new case passes and the old cases still pass. Then undo the change and explain in two sentences why changing a rubric is a contract decision (H.6), not a private edit.

## 5. Concepts to study before moving to the next stage

- Python `datetime` and `timedelta` (comparing times exactly).
- Dictionaries as counters and as groups.
- Sorting with a key function, and why tie-breakers make output repeatable.
- How the alert ID hash works at a high level and why IDs depend on the evidence.
- Precision, recall, false positives and false negatives.
- What a correlation is (needed for Stage 2A).
