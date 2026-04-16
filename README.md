# SentinelSDN Access Control System

## Project Goal
Allow only authorized hosts to communicate in an SDN network using a POX controller and OpenFlow rules.

## Rubric Coverage
This implementation directly addresses the required submission points:

1. Maintain whitelist of hosts:
      `policy.json` stores the authorized host IP list.
2. Install allow/deny rules:
      `controller.py` installs OpenFlow allow (priority 100) and deny (priority 200) rules.
3. Block unauthorized access:
      Traffic from unauthorized sources is dropped using deny flow entries.
4. Verify access control:
      Manual checks can be done with Mininet CLI pings.
5. Regression test (policy consistency):
      `test_access_control.py` repeats all policy test cases to ensure consistent behavior.

## Files

- `controller.py`: POX module that enforces the whitelist policy.
- `policy.json`: Configurable list of authorized host IP addresses.
- `topology.py`: Mininet topology launcher for manual verification.
- `test_access_control.py`: Automated verification + regression test runner.

## Environment

- Ubuntu/Linux with Mininet and Open vSwitch.
- Python 3.
- POX controller framework.

## Setup

1. Install dependencies:

```bash
sudo apt update
sudo apt install -y mininet python3-pip
```

2. Install POX (if not already installed):

```bash
cd ~
git clone https://github.com/noxrepo/pox.git
```

3. Copy project files into POX extension folder:

```bash
cp controller.py ~/pox/ext/sdn_access_control.py
cp policy.json ~/pox/ext/policy.json
```

## Run The Project

Open two terminals.

Terminal 1 (start controller):

```bash
cd ~/pox
python3 pox.py log.level --INFO sdn_access_control
```

Terminal 2 (start topology):

```bash
sudo python3 topology.py
```

In Mininet CLI, verify behavior:

```bash
h2 ping -c 2 h3
h1 ping -c 2 h3
h1 ping -c 2 h2
h4 ping -c 2 h1
h4 ping -c 2 h2
sh ovs-ofctl dump-flows s1
```

Expected:

- pings between h1 and h3 should work.
- pings involving h2 or h4 as source should fail.
- pings from h4 should fail.
- flow table should show deny entries with `priority=200`.

## Automated Tests

With the POX controller running, execute:

```bash
sudo python3 test_access_control.py
```

The script validates:

1. Full host-pair policy matrix against expected allow/deny outcomes.
2. Same full matrix rerun for regression consistency.
3. Both allow and deny flow rules are installed.

Exit status:

- `0`: all tests passed.
- `1`: one or more tests failed.

## Customize Whitelist

Edit `policy.json`:

```json
{
  "authorized_hosts": [
       "10.0.0.1",
                   "10.0.0.3"
  ]
}
```

After editing, restart POX controller so policy reloads.
