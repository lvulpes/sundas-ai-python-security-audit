# DF-017 login and file activity investigation

**All records, accounts, hosts, addresses and file paths are invented. The referenced files themselves are not supplied.**

## Case brief

A training evidence portal recorded repeated login failures and file-access
events on 20 October 2026. Determine which successful sessions meet the stated
rule and what subsequent downloads are recorded. Prioritise a session for
review without assuming an intrusion or attributing activity to a person.

The exports are deliberately unsorted and contain duplicate and malformed
records. Their timestamps use Z and +01:00 offsets. Assume both sources use
the same session-ID namespace. Clock accuracy, log completeness and the
real-world identity behind an account have not been independently established.

## Run from this folder

Python 3.10 or newer, standard library only. No notebook, pip install or API key.

| Purpose | macOS or Linux | Windows PowerShell |
| --- | --- | --- |
| Run starter or full analysis | `python3 analyze_case.py` | `py analyze_case.py` |
| Run login stage only | `python3 analyze_case.py --stage logins` | `py analyze_case.py --stage logins` |
| Check function 1 | `python3 check_solution.py LoginChecks` | `py check_solution.py LoginChecks` |
| Check function 2 | `python3 check_solution.py DownloadChecks` | `py check_solution.py DownloadChecks` |
| Run all checks | `python3 check_solution.py` | `py check_solution.py` |

If Windows does not recognise `py`, use `python` after checking that
`python --version` reports Python 3.10 or newer. Otherwise install Python 3.

Implement only `find_login_sequences` and `correlate_downloads` in
`analyze_case.py`. Their docstrings are the exact contracts. The supplied
loader, evidence, manifest and tests remain unchanged.

## Rules and field meanings

1. For every SUCCESS at T, group on `(username, source_ip, host)` and count
   FAIL events where **T - 5 minutes <= time < T**. Flag at least three.
   Each success is evaluated independently; earlier successes do not reset
   the window. A failure may support more than one alert.
2. Join file events using **username AND host AND session_id**. Keep only
   `action == "DOWNLOAD"`, `result == "SUCCESS"`, and **T <= time <= T + 10 minutes**.
   Count events, even if their paths repeat. Sum their integer bytes values.
   Retain alerts with zero matches. Sort by descending byte total, then time
   and success event ID. This ranking measures recorded volume, not guilt.
3. `event_id` identifies one event within its source. `session_id` links the
   two sources. `bytes` is the transfer size recorded by the application;
   independent transfer completion and destination evidence are not supplied.

## Evidence handling supplied for you

`evidence_tools.py` verifies the original CSV byte hashes against
`evidence_manifest.json`, trims outer whitespace, validates rows, requires
explicit timezone offsets, converts times to UTC and byte strings to integers,
and removes identical repeated event IDs. It records duplicate and rejected
CSV row numbers in `audit.json`. Conflicting versions of an ID stop analysis.
Rejected rows remain in the source; they are excluded from computed findings.

The starter writes `audit.json` before stopping at the first TODO. Function 1
adds `login_alerts.json`; the completed program adds `summary.json`. Rerun after
every change: old output files can be stale. A hash match demonstrates agreement
with this supplied baseline; it does not establish authenticity or completeness.
`.gitattributes` preserves CSV bytes through Git on all operating systems.

## Verified results -- complete this section
| Source       | Data rows excluding header | Accepted unique | Duplicate | Rejected |
| ---  | --- | --- | ---   | --- |
| auth_log.csv | 60                         | 54              | 1         | 5        |
| file_log.csv | 35                         | 30              | 1         | 4        |

- SHA-256 check outcome and what it establishes: The outcome is a pass in both cases. Both evidence files hashes were supplied. The analysis checks the hash against the manifest when processing the files. A test verifies that the SHA256 hashes do not change. It establishes authenticity, the files are identical to the files supplied, so they have not been changed during the analysis.
auth_log.csv: 9011778a7687a41e54da4ba96bd6597bf74252c9715572e2daac2615bebfc3d7
file_log.csv: 394afab97ca10d01347051f4862bf6b04f5937df41cd3d334c85898faa4feb73
- One rejected event ID and the exact rejection reason: "event_id": "A903","reason": "'999.1.1.1' does not appear to be an IPv4 or IPv6 address"
- Number of flagged successful sessions: 3: A005, A014, A018

| Success ID | Account     | Session | Supporting failure IDs | Download IDs     | Event count | Total bytes |
| ---  | --- | --- | ---   | --- | --- | --- |
| A005       | analyst01   | S-104   | A002, A003, A004       | F001, F002, F003 | 3           | 5509120     |
| A014       | backup_svc  | S-204   | A011, A012, A013       | -                | 0           | 0           |
| A018       | analyst02   | S-304   | A015, A016, A017       | F013             | 1           | 2048        |

## Manual evidence check -- do this without asking AI to count for you

For the highest-volume flagged session, find every supporting failure, the
success and every qualifying download in the original CSV files. Record their
original timestamps and UTC equivalents. Add rows as needed.

| Source and event ID | Original timestamp          | UTC timestamp          | What the row records       |
| --- | --- | --- | --- |
| auth_log.csb, A002    | 2026-10-20T08:58:00Z      | 2026-10-20T08:58:00Z   | Failed login                                    |
| auth_log.csv, A003    | 2026-10-20T09:00:00Z      | 2026-10-20T08:58:00Z   | Failed login                                    |
| auth_log.csv, A004    | 2026-10-20T10:01:00+01:00 | 2026-10-20T09:01:00Z   | Failed login                                    |
| auth_log.csv, A005    | 2026-10-20T09:03:00Z      | 2026-10-20T09:03:00Z   | Successful malicious login                      |
| file_log.csv, F001    | 2026-10-20T09:05:00Z      | 2026-10-20T09:05:00Z   | download of evidence_export.zip (5242880 bytes) |
| file_log.csv, F002    | 2026-10-20T10:07:00+01:00 | 2026-10-20T09:07:00Z   | download of interview_notes.pdf (262144 bytes)  |
| file_log.csv, F003    | 2026-10-20T09:13:00Z      | 2026-10-20T09:13:00Z   | download of hashes.txt (4096 bytes)             |

- Manual sum of download bytes, showing the addition: 5242880 + 262144 + 4096 = 5509120
- A001 versus A002: which qualifies for the A005 window and why? A002, A001 is outside of the time window by 1 second
- F003 versus F004: which qualifies for the A005 follow-up and why? F003 qualifies but not F004 which is one second outside the accepted time window
- Why F005 is excluded even though the account matches: F005 does not have a matching session id (S-OTHER)
- One +01:00 timestamp and its equivalent UTC time: 2026-10-20T10:01:00+01:00, 2026-10-20T09:01:00Z
- One limitation of excluding malformed records: Malformed records might descrbe real events, excluding them can weaken the analysis

## Checks actually run

Command, date and actual final result (paste output, including failures if any):

```text
python analyze_case.py 
SHA-256 checks match the supplied manifest.
auth_log.csv: 60 rows; 54 accepted; 1 duplicate; 5 rejected.
file_log.csv: 35 rows; 30 accepted; 1 duplicate; 4 rejected.
Saved audit.json. A hash match does not prove origin or completeness.
Found 3 login sequences; saved login_alerts.json.
Saved summary.json. Verify event IDs against both original CSV files.
A005 analyst01 S-104: 3 failures, 3 downloads, 5509120 bytes
A018 analyst02 S-304: 3 failures, 1 downloads, 2048 bytes
A014 backup_svc S-204: 3 failures, 0 downloads, 0 bytes
```

All 21 supplied checks should pass. Passing these checks is limited validation
of the stated classroom rule, not certification of a forensic tool.

``` terminal
----------------------------------------------------------------------
Ran 21 tests in 0.007s

OK
hugin@fedora:~/code/sundas-ai-python-security-audit/exercise/Forensics_Exercise_Student_Pack$ 

```

## AI interpretation and our final finding

Prompt 3 response about the overstated claim (keep the actual response):

> Response

Unsupported parts (97 words):
1. "Belongs to the attacker": analyst01 is an account name, and nothing supplied links it to a person. Failures A002–A004 followed by success A005 meet a review rule; they don't establish an attack.
2. "This person stole evidence": F001–F003 record three successful DOWNLOAD events (5,509,120 bytes) in S-104. They don't show who acted, whether access was authorised, file contents, or that data left the system.
3. "Authentic and complete": the hashes show only that the files match the supplied manifest. 5 auth rows and 4 file rows were rejected, so the usable record is known to be incomplete.

Rewritten claim:
Session S-104 (account analyst01) met the review rule: failures A002–A004 (08:58:00Z–09:01:00Z) were followed by successful login A005 at 09:03:00Z and successful download events F001–F003 (09:05:00Z–09:13:00Z) totalling 5,509,120 bytes, the highest recorded volume of the three flagged sessions. The logs match the supplied SHA-256 baseline, which shows they are unchanged since that manifest was produced but not that they are authentic or complete, and these records alone do not identify who used the account or show that data left the system.

One claim we corrected or independently verified, with event IDs:
Session S-104 (account analyst01) met the review rule: failures A002-A004. They were followed by a successful login at 09:03:00Z (A005). 3 successful downloads followed (F001-F003) totalling 5509120 bytes.

### Final 180-220 word finding, reviewed and edited by the pair:

#### Observation
Session S-104 (account analyst01, source IP 203.0.113.44, host DF-PORTAL01) met the review rule: failures A002, A003 and A004 between 08:58:00Z and 09:01:00Z preceded successful login A005 at 09:03:00Z. Within the following ten minutes, the portal recorded three successful DOWNLOAD events, F001, F002 and F003 (09:05:00Z to 09:13:00Z), totalling 5,509,120 bytes. For comparison, session S-304 (analyst02; failures A015 to A017 before success A018 at 10:05:00Z) recorded one qualifying download, F013, of 2,048 bytes; F014 (2,000,000 bytes) at 10:15:01Z fell one second outside its window. S-104 is prioritised for review on recorded volume alone.

#### Inference and limitations.
These records do not identify who used the account, show whether access was authorised, or prove that data left the system. First, 5 auth and 4 file rows were rejected, including F902, a malformed S-104 download, so totals may be understated. Second, matching SHA-256 hashes show consistency with the supplied manifest only, not authenticity or completeness. A plausible benign explanation is that the account holder mistyped a password, then retrieved case material for routine work. Furthermore, a major limitation is the 10 minute time window limit, which misses several interesting events (like F014 where 2MB is downloaded).

#### Next requests.
Portal web-server or proxy logs showing client IP and bytes actually sent for F001 to F003, and identity-provider records of the authentication behind A005.


## AI use and pair review

- Names of both partners: Martin Elfvelin
- GenAI tool/ChatGPT date and displayed model: Claude Code (using Claude Opus 5.5)
- Prompts used and what they produced: I used the prompts from the prompts.txt, with additional prompts from myself to help understand the results. 
- One follow-up question or correction, with a short response excerpt: N/A
- Results of code and evidence checks performed: All tests pass, output has been validated.


## Submit

Submit one public repository URL per pair through the course route. Include the ten
starter project files and the newly generated `audit.json`, `login_alerts.json`,
and `summary.json`. Complete this README. The repository needs a starting
commit and a finished commit. The accompanying student guide gives the
90-minute schedule; `GitHub_CLI_Guide.docx` covers setup and upload.
Only synthetic exercise files belong in this repository. Keep credentials out.

Optional stretch after the core task: use the interactive Python console to
compare `min_failures=2` with `min_failures=3`, without changing the defaults or
original evidence. Which extra session appears, and does that change what you
can conclude? Record this separately from the required default output.
