# Evidence folder convention

One subfolder per test run, named `<project>_<environment>_<yyyy-mm-dd>/`, containing:

- `screenshots/` — UI evidence (masked: no OTP/password visible in the frame)
- `requests/` — masked request logs (`MaskUtil` already applied) named `<findingId>_<n>.txt`
- `responses/` — masked response logs, same naming
- `index.md` — one line per finding id linking to its evidence files

`ReportEngine` writes links into the VAPT/Retest report's "Evidence" column pointing
at paths under this folder — keep the folder alongside the report when sharing it.

Nothing in this folder should ever contain a literal password, OTP, bearer token,
PAN, Aadhaar number or card number — if you ever find one, delete the file and
re-run; it means a step bypassed `MaskUtil` and that step needs a fix.
