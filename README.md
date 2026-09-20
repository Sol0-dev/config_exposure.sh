### config_exposure_scan.sh
______________________________________________________________________________

 Checks a list of hosts for common publicly-exposed sensitive files
 (config.json, .env, .git/config, etc.) -- httpx/nuclei style CLI.

 Runs in the FOREGROUND: you see output live in your terminal (verbose
 or quiet), the script blocks until the scan finishes, then prints a
 summary report -- just like other bug bounty scanners. No tail -f
 needed, nothing hidden in a log file.
_____________________________________________________________________________

## USAGE:
```
   ./config_exposure_scan.sh -l urls.txt [-c concurrency] [-v] [-q]

 FLAGS:
   -l <file>       Input file, one base URL per line (required)
   -c <n>          Concurrency (default: 6)
   -v              Verbose: print every request's result live as it happens
   -q              Quiet (default): only progress ticks + final summary
   -h              Show this help
```
______________________________________________________________________________

## OUTPUT FILES (still written for later reference):
```
   found.txt        -> ONLY confirmed HTTP 200 hits with real content
   all_results.log  -> full log of every path checked and its status
```
______________________________________________________________________________
Termux-safe: single curl call per check (low process count) so Android
doesn't kill the session, and auto-holds a wake-lock (if available)
for the duration of the scan so the screen can lock without it dying.

### validate.sh (Fixed & Smarter)
______________________________________________________________________________
```
Verifies items in found.txt for genuine valuable secrets/configurations
and filters out empty stubs / false positives.
```
