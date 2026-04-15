# soc-alert-investigation

## Objective
Investigate suspicious login activity using log analysis

## Scenario
Multiple failed login attempts detected on a Linux system

## Tools Used
- Linux logs
- grep
- awk
- sort

## Steps Taken
1. Reviewed authentication logs
2. Identified repeated failed login attempts
3. Found source IP responsible
4. Analyzed frequency of attempts

## Commands Used
grep "Failed password" auth.log
grep "Failed password" auth.log | awk '{print $11}' | sort | uniq -c

## Findings
Repeated failed login attempts from a single IP indicate brute force behavior

## Risk
Unauthorized access if attacker succeeds

## Recommendation
- Lock accounts after failed attempts
- Enable MFA
- Monitor logs


