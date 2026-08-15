#SOC Investgigation 01 - Unexpected TCP Service

Scenario
- Investigate an unexpected TCP service on '10.0.2.15'

Investigation:

bash
sudo ss -tlnp

Found:
0.0.0.0:8080 -> python3 (PID 12663)

checked the process:
ps -p 12663 -f

found:
python3 -m http.server 8080

Checked the parent Process:
ps -p 12457 -f

founder:
/user/bin/bash

Conclusion:
The service was benign. It was intentionally started for the lab.

Key lesson:
Alert -> Port -> Process -> Parent Process -> Asses
