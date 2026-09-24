# NetOsis --- New Project Bootstrap for Cursor Agent

## IMPORTANT CONTEXT

This is a **brand-new NetOsis project**.

The local project directory is intentionally empty.

Do NOT assume this is the old GitHub `NetOsis` repository. Do NOT clone,
pull, copy, merge, or reuse the old GitHub implementation unless the
user explicitly asks for it later.

The goal is to build a fresh NetOsis implementation from scratch using
the locked architecture and the existing physical/virtual lab
environment described below.

The repository should eventually be publishable as a new Git repository.

------------------------------------------------------------------------

# 1. STARTING STATE

The user has an empty local project directory similar to:

``` text
~/Documents/NetOsis/
```

The old GitHub project is NOT the source code for this implementation.

The new project should start with:

``` text
NetOsis/
```

and be initialized as a clean project.

First actions:

``` bash
pwd
ls -la
git status
```

If the directory is empty, create the project structure from scratch.

If it already contains files, inspect them before modifying anything.

Do not delete existing files automatically.

------------------------------------------------------------------------

# 2. PROJECT GOAL

NetOsis is a resource-efficient adaptive deception / high-interaction
honeypot environment.

The system should:

1.  expose believable services to an attacker
2.  provide a high-interaction fake environment
3.  maintain authoritative virtual host/network state
4.  record attacker telemetry
5.  map behavior to MITRE ATT&CK
6.  construct a dynamic attack graph
7.  maintain an actor/behavior profile
8.  apply deterministic policy
9.  adapt deception based on observable behavior
10. optionally use RAG + LLM for natural interaction
11. optionally use a GNN for advanced graph-based scoring
12. optionally move genuinely untrusted execution into a disposable VM
    sandbox

The system must remain resource-efficient and explainable.

------------------------------------------------------------------------

# 3. LOCKED ARCHITECTURE

``` text
                         ATTACKER
                            |
                            v
                    +---------------+
                    | Public HHP     |
                    | Web / SSH etc. |
                    +-------+-------+
                            |
                            v
                    +---------------+
                    | HHP Runtime    |
                    |               |
                    | Fake Shell     |
                    | Virtual Hosts  |
                    | Fake Services  |
                    +-------+-------+
                            |
                         Events
                            |
                            v
                    +---------------+
                    | Telemetry +   |
                    | Event Store   |
                    +-------+-------+
                            |
              +-------------+-------------+
              |                           |
              v                           v
       MITRE ATT&CK Mapper          Actor Profile
              |                           |
              +-------------+-------------+
                            |
                            v
                    Dynamic Attack Graph
                            |
                            v
                    Policy / Risk Engine
                            |
              +-------------+-------------+
              |                           |
              v                           v
       Adaptive Deception          Disposable Sandbox
              |                           |
       +------+------+                    |
       |             |                    |
       v             v                    v
   More virtual   Canaries          Maximum telemetry
   infrastructure / artifacts
       |
       v
    RAG + LLM
       |
       v
    ATTACKER
```

Core spine:

``` text
network isolation
        ->
telemetry
        ->
actor/profile
        ->
attack graph
        ->
MITRE ATT&CK
        ->
policy
        ->
adaptive deception
```

------------------------------------------------------------------------

# 4. CRITICAL ARCHITECTURAL RULE

## The LLM is NOT the controller

The LLM must not be:

-   the source of truth
-   the firewall
-   the network simulator
-   the security boundary
-   the sole risk engine
-   responsible for inventing host state

Authoritative state comes from structured configuration/state.

Use:

``` text
YAML / JSON structured state
          |
          v
deterministic command engine
          |
          +---- simple command
          |          |
          |          v
          |     deterministic result
          |
          +---- complex interaction
                     |
                     v
                  RAG + LLM
                     |
                     v
             state-constrained result
```

The policy engine decides what adaptive action is permitted.

The LLM may recommend, but deterministic policy validates.

------------------------------------------------------------------------

# 5. REAL LAB ARCHITECTURE

## Management / upstream network

``` text
172.30.226.0/24
```

Known Proxmox:

``` text
vmbr0
172.30.226.7/24
gateway 172.30.226.254
```

This network is outside the FYP OPNsense VLAN architecture.

It is used for lab management/upstream/jump-box-related connectivity.

Do NOT expose this network to attackers.

Do NOT redesign it into an OPNsense internal management VLAN.

------------------------------------------------------------------------

# 6. FYP TRUNK

Proxmox FYP bridge:

``` text
vmbr1
```

`vmbr1` is VLAN-aware and carries the FYP VLANs toward OPNsense.

------------------------------------------------------------------------

# 7. LOCKED OPNsense VLAN PLAN

  ----------------------------------------------------------------------------------------
               VLAN Name                Subnet            Gateway          Purpose
  ----------------- ------------------- ----------------- ---------------- ---------------
                 10 FINANCE_VLAN10      192.168.10.0/24   192.168.10.254   Finance

                 20 OPERATIONS_VLAN20   192.168.20.0/24   192.168.20.254   Operations

                 30 ENTERPRISE_VLAN30   192.168.30.0/24   192.168.30.254   Enterprise /
                                                                           public-facing
                                                                           test services

                 40 SOC_VLAN40          192.168.40.0/24   192.168.40.254   SOC / telemetry
                                                                           / controller /
                                                                           RAG / LLM
  ----------------------------------------------------------------------------------------

Existing VLAN 250 remains.

Use `.254` as the gateway for the current FYP VLAN plan.

Use `/24` networks.

Do not silently revert to older spreadsheet values such as `.1` gateways
or `/28` networks.

------------------------------------------------------------------------

# 8. REAL EMPLOYEE ENVIRONMENT

There will be six real employee VMs.

``` text
FINANCE
├── FIN-USER-01
└── FIN-USER-02

OPERATIONS
├── OPS-USER-01
└── OPS-USER-02

ENTERPRISE
├── ENT-USER-01
└── ENT-USER-02
```

Addresses:

``` text
FIN-USER-01 -> 192.168.10.10
FIN-USER-02 -> 192.168.10.11

OPS-USER-01 -> 192.168.20.10
OPS-USER-02 -> 192.168.20.11

ENT-USER-01 -> 192.168.30.10
ENT-USER-02 -> 192.168.30.11
```

Use Proxmox SDN VNets:

``` text
FIN
OPS
ENT
```

The final employee VMs must not remain on `vmbr0`.

------------------------------------------------------------------------

# 9. EMPLOYEE TEMPLATE

VM 102 has been used as the employee base/template.

It was observed running:

``` text
Ubuntu 26.04.1 LTS
```

An earlier design mentioned Ubuntu 24.04.

Do NOT silently rebuild or change the OS version.

If the agent discovers VM 102 or template-related configuration,
document it and ask the user before changing the OS version.

The desired workflow is:

``` text
Ubuntu base
     |
     v
common employee configuration
     |
     v
Cloud-Init / clone customization
     |
     v
Proxmox template
     |
     +---- FIN-USER-01
     +---- FIN-USER-02
     +---- OPS-USER-01
     +---- OPS-USER-02
     +---- ENT-USER-01
     +---- ENT-USER-02
```

Do not bake employee-specific IP addresses into the template.

------------------------------------------------------------------------

# 10. DECEPTION HOST MODEL

Do NOT create one VM for every fake host.

Most apparent hosts should be virtual/emulated.

Example:

``` text
deception/
├── hosts/
│   ├── finance-db.yml
│   ├── finance-workstation.yml
│   ├── ops-server.yml
│   └── enterprise-web.yml
├── networks/
│   ├── vlan10.yml
│   ├── vlan20.yml
│   └── vlan30.yml
├── artifacts/
│   ├── finance/
│   ├── operations/
│   └── enterprise/
└── scenarios/
    └── lateral-movement.yml
```

Each virtual host may define:

-   hostname
-   IP
-   VLAN
-   role
-   OS
-   services
-   ports
-   users
-   filesystem
-   processes
-   packages/version hints
-   artifacts
-   fake credentials
-   network configuration
-   relationships to other hosts

The state must remain internally consistent.

------------------------------------------------------------------------

# 11. HHP / FAKE SHELL

Initial interaction:

``` text
login
  ->
fake shell
  ->
pwd
ls
cat
whoami
ps
ip addr
ip route
```

Simple commands must be deterministic.

For example:

``` text
pwd
```

should be answered from the virtual host state.

``` text
ls
```

should use the virtual filesystem.

``` text
whoami
```

should use the virtual user state.

Do not send every command to the LLM.

------------------------------------------------------------------------

# 12. TELEMETRY

Every meaningful interaction should produce structured telemetry.

Example:

``` json
{
  "timestamp": "...",
  "session_id": "...",
  "actor_id": "...",
  "source_ip": "...",
  "target_host": "...",
  "target_ip": "...",
  "event_type": "command",
  "command": "whoami",
  "result": "...",
  "virtual": true,
  "technique": null,
  "technique_confidence": 0.0
}
```

Pipeline:

``` text
raw event
   ->
normalization
   ->
behavior interpretation
   ->
ATT&CK mapping
   ->
attack graph update
   ->
policy evaluation
```

Keep raw telemetry separate from derived analytics.

------------------------------------------------------------------------

# 13. MITRE ATT&CK

Do not blindly map every command.

Use:

``` text
raw event
   ->
behavior interpretation
   ->
ATT&CK technique
   ->
confidence
```

Examples:

``` text
service scanning
    -> Network Service Scanning / Discovery

whoami
    -> System Owner/User Discovery

ip addr
    -> System Network Configuration Discovery

ip route
    -> System Network Configuration Discovery

credential attacks
    -> appropriate Credential Access context

lateral movement
    -> appropriate Lateral Movement context

payload transfer
    -> appropriate technique depending on observed behavior
```

Mapping must remain context-aware.

------------------------------------------------------------------------

# 14. DYNAMIC ATTACK GRAPH

Represent:

``` text
ACTOR
  |
  +-- interacted_with --> HOST
  |
  +-- executed --> COMMAND
  |
  +-- discovered --> HOST
  |
  +-- accessed --> ARTIFACT
  |
  +-- triggered --> CANARY

COMMAND
  |
  +-- maps_to --> ATT&CK_TECHNIQUE

HOST
  |
  +-- exposes --> SERVICE
  |
  +-- belongs_to --> VLAN

HOST_A
  |
  +-- can_reach --> HOST_B
```

The graph changes as the attacker interacts.

Example:

``` text
t0 actor -> HHP

t1 actor -> discovery

t2 actor -> network discovery

t3 actor -> virtual host

t4 actor -> lateral movement

t5 actor -> collection/canary
```

------------------------------------------------------------------------

# 15. RISK BASELINE

Start with a deterministic, explainable baseline.

Example experimental weights:

``` text
Discovery          +1
Credential attack  +3
Successful access  +4
Lateral movement   +5
Payload transfer   +5
Execution          +8
Persistence        +8
Canary interaction +6
```

These are experimental starting values, not ground truth.

Later evaluate a GNN against this baseline.

Potential outputs:

``` text
Discovery likelihood
Execution likelihood
Lateral movement likelihood
Collection likelihood
```

Do not make GNN a dependency of the first working system.

------------------------------------------------------------------------

# 16. ADAPTIVE DECEPTION

The policy engine selects from predefined actions.

``` text
D01 = expose fake host
D02 = expose fake service
D03 = expose fake credential
D04 = expose fake document
D05 = deploy canary
D06 = increase telemetry
D07 = reveal virtual network segment
D08 = activate disposable sandbox
```

Behavioral levels:

``` text
LOW
MEDIUM
HIGH
CRITICAL
```

These are based on observable behavior and confidence.

Do not build a vague "good attacker / bad attacker" classifier.

------------------------------------------------------------------------

# 17. CANARIES

Canaries should resemble believable enterprise documents/artifacts.

Avoid obvious trap names.

When accessed, record:

-   actor/session
-   source
-   artifact
-   time
-   action
-   resulting policy change

Canary interaction becomes telemetry.

------------------------------------------------------------------------

# 18. SANDBOX

For genuinely untrusted malware:

``` text
HHP
 |
 v
policy engine
 |
 v
disposable VM / microVM-style sandbox
 |
 v
maximum telemetry
```

Do not execute unknown malware on the Fedora host.

Do not treat an ordinary container as the fundamental malware security
boundary.

Kubernetes is optional future orchestration, not the initial security
boundary.

------------------------------------------------------------------------

# 19. USER'S EXISTING VPN + FREERDP WORKFLOW

The user has an existing Fedora-side directory:

``` text
/home/mania/Documents/server/
```

Known files include:

``` text
Aheed_VPN_aheed.ovpn
openvpn-auth.txt
Open_VPN_Server_eman.ovpn
start.sh
jumpbox/
jumpbox-rdp.pid
openvpn.pid
openvpn.log
```

Known jump-box/RDP target:

``` text
172.30.227.1
```

The user already has a workflow that starts:

``` text
OpenVPN
   ->
tun0
   ->
FreeRDP
   ->
Jump Box
```

The Cursor agent may inspect this workflow if it has local terminal
control.

If it can safely control the user's workstation, it may:

-   check whether VPN is running
-   check whether `tun0` exists
-   check whether FreeRDP is running
-   invoke the existing `start.sh` when appropriate
-   report status

If it cannot control the workstation, create scripts/configuration that
the user can execute manually.

------------------------------------------------------------------------

# 20. SECRET HANDLING

NEVER put these into the new repository:

``` text
*.ovpn
openvpn-auth.txt
passwords
private keys
tokens
cookies
.env files containing secrets
credential-bearing logs
```

Do not print secrets.

The new repository should only contain references/documentation
describing where the user's local secret files are expected to exist.

Example:

``` text
HOST_VPN_CONFIG=/home/mania/Documents/server/Aheed_VPN_aheed.ovpn
HOST_VPN_AUTH=/home/mania/Documents/server/openvpn-auth.txt
```

These values should belong in local environment configuration, not Git.

------------------------------------------------------------------------

# 21. NEW REPOSITORY STRUCTURE

Build this progressively:

``` text
NetOsis/
├── README.md
├── ARCHITECTURE.md
├── SECURITY.md
├── .gitignore
│
├── docs/
│   ├── network.md
│   ├── deployment.md
│   ├── threat-model.md
│   └── attack-flow.md
│
├── config/
│   ├── network/
│   │   ├── vlans.yml
│   │   ├── hosts.yml
│   │   └── services.yml
│   ├── deception/
│   └── policy/
│
├── deception/
│   ├── runtime/
│   ├── command_engine/
│   ├── hosts/
│   ├── services/
│   ├── artifacts/
│   └── scenarios/
│
├── telemetry/
│   ├── schema/
│   ├── collectors/
│   ├── normalization/
│   └── storage/
│
├── attack_graph/
│   ├── model/
│   ├── builder/
│   └── queries/
│
├── mitre/
│   ├── mappings/
│   └── mapper/
│
├── policy/
│   ├── rules/
│   └── engine/
│
├── rag/
│   ├── retrieval/
│   └── prompts/
│
├── llm/
│   ├── interface/
│   └── adapters/
│
├── scoring/
│   ├── baseline/
│   └── gnn/
│
├── sandbox/
│   ├── controller/
│   └── profiles/
│
├── ops/
│   ├── host/
│   ├── proxmox/
│   └── deployment/
│
├── scripts/
│   └── lab-access/
│
└── tests/
    ├── unit/
    ├── integration/
    └── scenarios/
```

Do not create fake implementations just to populate every directory.

Create components when they become part of the working system.

------------------------------------------------------------------------

# 22. FIRST VERTICAL SLICE

This is the first actual development target:

``` text
Public HHP
    |
    v
login
    |
    v
fake shell
    |
    +--> pwd
    +--> ls
    +--> cat
    +--> whoami
    |
    v
structured telemetry event
    |
    v
ATT&CK mapping
    |
    v
attack graph update
    |
    v
one deterministic adaptive deception action
```

This must work before adding:

-   GNN
-   Kubernetes
-   malware execution
-   complex orchestration
-   large SIEM stacks
-   multiple LLM agents

------------------------------------------------------------------------

# 23. IMPLEMENTATION ORDER

## Phase 0 --- project bootstrap

Do now:

``` text
empty project
   ->
Git repository
   ->
.gitignore
   ->
README
   ->
ARCHITECTURE
   ->
SECURITY
   ->
network configuration
```

No infrastructure modification yet.

## Phase 1 --- deterministic HHP

Build:

``` text
session
shell
virtual filesystem
virtual users
virtual host state
basic commands
```

## Phase 2 --- telemetry

Build:

``` text
event schema
event generation
event storage
```

## Phase 3 --- ATT&CK

Build:

``` text
behavior interpretation
technique mapping
confidence
```

## Phase 4 --- attack graph

Build:

``` text
nodes
edges
event-to-graph updates
queries
```

## Phase 5 --- policy

Build:

``` text
observable behavior
   ->
baseline risk
   ->
allowed deception action
```

## Phase 6 --- adaptive deception

Build:

``` text
fake hosts
fake services
fake credentials
fake artifacts
canaries
progressive disclosure
```

## Phase 7 --- RAG + LLM

Only now integrate the LLM.

## Phase 8 --- GNN experiment

Compare:

``` text
deterministic baseline
        vs
GNN
```

## Phase 9 --- optional disposable sandbox

Add only after containment architecture is verified.

------------------------------------------------------------------------

# 24. FIRST ACTIONS FOR CURSOR

When this document is supplied to Cursor Agent, do the following in
order.

### Step 1

Inspect:

``` bash
pwd
ls -la
git status
```

### Step 2

Confirm that this is a fresh project.

Do not clone the old GitHub NetOsis repository.

### Step 3

Create:

``` text
.gitignore
README.md
ARCHITECTURE.md
SECURITY.md
docs/network.md
config/network/vlans.yml
```

### Step 4

Create a local development configuration template such as:

``` text
.env.example
```

It may document variables such as:

``` text
VPN_CONFIG_PATH=
VPN_AUTH_PATH=
JUMPBOX_RDP_TARGET=
```

But never put actual credentials in `.env.example`.

### Step 5

Create safe host-access scripts:

``` text
scripts/lab-access/start-vpn-rdp.sh
scripts/lab-access/stop-vpn-rdp.sh
scripts/lab-access/status-vpn-rdp.sh
```

These should reference local paths/environment variables rather than
embedding secrets.

### Step 6

Create the authoritative network model:

``` text
config/network/vlans.yml
```

with:

``` yaml
management:
  subnet: 172.30.226.0/24
  proxmox_ip: 172.30.226.7/24
  gateway: 172.30.226.254
  bridge: vmbr0

fyp:
  bridge: vmbr1
  vlans:
    - id: 10
      name: FINANCE
      subnet: 192.168.10.0/24
      gateway: 192.168.10.254

    - id: 20
      name: OPERATIONS
      subnet: 192.168.20.0/24
      gateway: 192.168.20.254

    - id: 30
      name: ENTERPRISE
      subnet: 192.168.30.0/24
      gateway: 192.168.30.254

    - id: 40
      name: SOC
      subnet: 192.168.40.0/24
      gateway: 192.168.40.254
```

### Step 7

Create documentation for the six employee VMs.

### Step 8

Stop and show the user:

-   created files
-   architecture
-   detected host environment
-   any assumptions
-   any proposed infrastructure changes

Do not automatically reconfigure Proxmox/OPNsense.

------------------------------------------------------------------------

# 25. PROHIBITED AUTOMATIC ACTIONS

The agent must NOT automatically:

-   delete VMs
-   delete disks
-   modify Proxmox bridges
-   change OPNsense firewall rules
-   change OPNsense interfaces
-   change VLAN configuration
-   change host routing
-   expose management networks
-   disable firewall protections
-   execute unknown malware
-   copy credentials
-   commit secrets
-   clone the old GitHub NetOsis implementation
-   overwrite an existing project without inspection

For infrastructure changes, prepare the exact change and ask for
approval.

------------------------------------------------------------------------

# 26. PROJECT QUALITY REQUIREMENT

Every implementation decision must be explainable in an FYP viva.

For every major component document:

``` text
Purpose
Architecture
Inputs
Outputs
Security assumptions
Failure modes
Tests
Resource requirements
```

Avoid "AI magic".

Avoid opaque autonomous behavior.

Prefer deterministic, observable components.

------------------------------------------------------------------------

# 27. FINAL PRINCIPLE

Build NetOsis from the architecture outward.

Do not start by writing a giant AI system.

Build:

``` text
network model
    ->
state model
    ->
HHP
    ->
telemetry
    ->
ATT&CK
    ->
attack graph
    ->
policy
    ->
adaptive deception
    ->
RAG/LLM
    ->
GNN
    ->
optional sandbox
```

The first goal is not a huge system.

The first goal is a small, working, measurable vertical slice that can
grow into the locked architecture.
