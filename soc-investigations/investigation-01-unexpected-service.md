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


## Scenario

An Unexpected Python process was discovered running on the system.

## Investigation

- identified process using ps
- Process: python3 -m http.server 8080
- PID: 12663
- Parent Process: /usr/bin/bash
- User: ferenzzo
- Confirmed listening on TCP port 8080
- Listening Address: 0.0.0.0:8080
- checked process start time
- Identified working directory: /home/ferenzzo/networking-fundamentals
- verified files exposed by the http server
- checked for active connections
- used lsof to examine open files and network sockets

## Finding

Python HTTP server was intentionally started for the lab

*Classification: Benign / Expected Activity *

## Key Lesson

A SOC investigation follows the evidence:
Process -> Parent -> User -> Network Activity -> Files -> Connections -> Classifications
