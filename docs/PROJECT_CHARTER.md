# Security Environment Control Platform

## Project Charter

**Repository:** `security-environment-control-plane`
**Product brand:** TBD — this charter intentionally uses a descriptive internal name, not a public-facing brand.
**Status:** Living architecture and product charter
**Audience:** Product, engineering, security, infrastructure, AI, and implementation agents

---

## 1. Mission

Build an enterprise-grade, AI-native platform for creating, operating, observing, validating, resetting, and reporting on controlled security environments.

This product is not a “cyber range” product in the narrow training-lab sense.

A cyber range is only one application of the platform.

The product is a control plane for secure, repeatable environments used for:

* security validation
* purple-team exercises
* red-team and blue-team simulations
* incident-response rehearsals
* SOC workflow validation
* malware-safe detonation environments
* customer demonstrations
* security tool integration testing
* secure application testing environments
* infrastructure attack-path simulations
* workforce training and academic exercises
* enterprise digital security environments

The platform must make complex security environments repeatable, isolated, auditable, visual, policy-controlled, and operationally safe.

---

## 2. Product Definition

The platform combines ideas from:

* VMware vCenter
* Kubernetes control planes
* Terraform and OpenTofu
* Ansible
* Cisco Packet Tracer
* security orchestration platforms
* SIEM and observability platforms
* AI copilots
* infrastructure digital twins

The platform owns the user experience, state model, lifecycle management, topology model, deployment planning, approval workflow, reporting, scoring, and integrations.

It does not attempt to replace mature infrastructure, security, monitoring, or offensive-security tools.

Instead, it orchestrates them through secure, versioned plugins.

---

## 3. Core Product Promise

An administrator should eventually be able to request:

> Create a five-team intermediate ransomware-response environment for a healthcare organization.

The platform should be able to propose and, after explicit approval, create:

* declarative environment definitions
* isolated per-team or per-tenant environments
* topology and network design
* virtual machines, containers, networks, and supporting infrastructure
* vulnerable systems and controlled attack paths
* monitoring and telemetry collection
* scoring objectives or validation checks
* participant/team assignments
* live topology visualization
* reset and destroy workflows
* audit trails
* after-action and executive reports

AI may assist with generation, validation, recommendation, explanation, and reporting.

AI must never bypass authorization, policy, approval gates, or infrastructure safety controls.

---

## 4. Product Philosophy

### 4.1 Control Plane First

The platform is the source of truth for:

* organizations
* users
* roles
* teams
* templates
* environment definitions
* immutable environment versions
* exercises and validation runs
* environment instances
* deployment plans
* workflow state
* inventory
* topology
* scoring
* reports
* audit events
* plugin configuration
* policy decisions

Underlying infrastructure is an execution target and source of observed state. It is not the authoritative system of record.

### 4.2 Open Source First

Use mature open-source projects whenever possible.

Examples include:

**Infrastructure**

* Proxmox
* OpenTofu
* Terraform
* Ansible

**Monitoring and Detection**

* Wazuh
* Security Onion
* Zeek
* Suricata
* Sysmon
* Velociraptor

**Telemetry and Observability**

* OpenSearch
* Grafana
* Prometheus
* Loki

**Scoring and Validation**

* CTFd
* custom validation engines

**Security Tooling**

* Kali Linux
* Metasploit
* Sliver
* BloodHound
* Impacket
* Burp Community

**Common Environment Targets**

* Ubuntu
* Windows Server
* Active Directory
* OWASP Juice Shop
* DVWA
* Metasploitable

The platform should orchestrate, normalize, secure, and visualize these systems rather than rebuild them.

### 4.3 Enterprise Quality Over Quick Hacks

Avoid architecture that only works for one lab, one hypervisor, one developer machine, or one scenario.

Every major component should support future growth into:

* multiple organizations
* multiple concurrent environments
* multiple infrastructure providers
* hybrid deployments
* long-running workflows
* failure recovery
* auditability
* secure credential handling
* plugin versioning
* backup and disaster recovery
* commercial deployment models
* managed or self-hosted offerings

---

## 5. Architecture Boundaries

The platform is organized into clear layers.

### Layer 1: Experience Plane

The frontend provides:

* administrator dashboard
* environment library
* environment builder
* scenario and exercise management
* team management
* deployment-plan approval
* Packet Tracer-style topology visualization
* environment monitoring
* live alerts and health overlays
* validation or scoring dashboards
* reports
* audit logs
* AI copilot

Primary client technology: React and TypeScript.

### Layer 2: Core Control Plane

The core API owns:

* authentication
* authorization
* RBAC
* organizations
* users
* teams
* templates
* environment definitions
* immutable versions
* inventory
* state
* audit events
* artifacts
* API contracts
* policy evaluation

The core API must not directly run OpenTofu, Terraform, Ansible, shell commands, or hypervisor API calls.

### Layer 3: Environment Definition Engine

The environment definition engine turns declarative environment definitions into validated, versioned, reproducible specifications.

It owns:

* schema validation
* versioning
* objectives
* team assignments
* network requirements
* VM and container roles
* vulnerability-pack references
* telemetry requirements
* validation logic
* scoring configuration
* resource policies
* required plugins

An immutable environment version is the canonical source of truth for every deployment.

### Layer 4: Orchestration Engine

The orchestration engine converts approved deployment plans into durable workflows.

It owns:

* dependency resolution
* deployment sequencing
* retries
* workflow recovery
* plugin execution coordination
* state reconciliation
* drift detection
* reset workflows
* destroy workflows
* event emission
* artifact collection

The orchestration engine must support long-running operations and resume safely after worker failures.

### Layer 5: Infrastructure as Code

OpenTofu or Terraform provisions resources such as:

* virtual machines
* containers
* networks
* VLANs
* bridges
* firewalls
* storage
* DNS
* DHCP
* load balancers
* cloud resources

OpenTofu is the initial preferred engine, but it must remain behind a provider-neutral runner interface.

### Layer 6: Configuration Management

Ansible configures provisioned systems, including:

* operating-system baselines
* services
* users and permissions
* agents and sensors
* telemetry forwarding
* vulnerabilities
* deliberately vulnerable configurations
* fake company data
* exercise assets
* cleanup actions

### Layer 7: Infrastructure Providers

Initial provider:

* Proxmox

Future providers:

* VMware vSphere
* Hyper-V
* AWS
* Azure
* GCP
* Kubernetes

Each provider must be implemented through a plugin or adapter. The core platform must not contain provider-specific business logic.

### Layer 8: Security Ecosystem

Security and observability tools are deployed and integrated through plugins.

Initial likely integrations:

* Kali Linux
* vulnerable Ubuntu target
* Wazuh
* CTFd

Future integrations:

* Security Onion
* Zeek
* Suricata
* Velociraptor
* OpenSearch
* Grafana
* Prometheus
* Loki
* Splunk
* Microsoft Sentinel

---

## 6. Architectural Invariants

These rules are mandatory unless changed through an approved Architecture Decision Record.

1. The control plane owns desired state. Providers report observed state.

2. Environment versions are immutable after creation.

3. Every deployment is linked to one exact environment version.

4. A deployment plan must be generated before execution.

5. Deployment plans require explicit approval before infrastructure execution.

6. The API must not directly execute privileged infrastructure actions.

7. Privileged actions occur only through isolated workflow workers and plugins.

8. Plugins communicate through versioned contracts.

9. The core database must not contain provider-specific columns that only apply to one integration.

10. Every mutation produces an immutable audit event.

11. Environment instances are isolated by default.

12. Cross-team, cross-environment, or external connectivity must be explicitly declared and approved.

13. AI may propose plans and generate artifacts, but it may not bypass policy, approval, authorization, or isolation controls.

14. Reset must restore a known-good baseline, not rely only on ad hoc cleanup.

15. Destroy must be idempotent and safe to retry.

16. Every external integration must support health reporting, capability discovery, and version tracking.

17. Environment workloads must never gain unrestricted access to management, home, corporate, or public networks by default.

---

## 7. Core Domain Model

### Organization

A tenant and operating boundary containing users, teams, templates, environments, plugins, policies, and audit data.

### User

A human or service identity authenticated through an OIDC-compatible identity provider.

### Role

An authorization role, such as:

* Platform Administrator
* Organization Administrator
* Environment Administrator
* Template Author
* Instructor
* Operator
* Observer
* Participant
* Auditor

### Team

A logical group assigned to one or more environment instances.

### Environment Template

A reusable environment concept, such as:

* Web Breach 101
* Active Directory Attack Path
* Ransomware Response
* Healthcare SOC Simulation
* Application Security Validation Environment

### Environment Version

An immutable declarative snapshot of an Environment Template.

It defines the exact topology, assets, rules, objectives, integrations, policies, and dependencies required for deployment.

### Exercise or Validation Run

A scheduled or active execution of one exact Environment Version.

An exercise may contain multiple teams and multiple isolated Environment Instances.

### Environment Instance

A single isolated environment assigned to one team, participant group, customer, workflow, or validation target.

A five-team exercise generally creates five environment instances.

Each environment instance may include:

* isolated networks
* VMs and containers
* target systems
* simulated adversary hosts
* sensors
* telemetry configuration
* topology nodes
* score or validation state
* health state
* lifecycle state

### Deployment Plan

A deterministic plan generated from an Environment Version and target environment.

The plan describes exactly what will be created, changed, configured, reset, or destroyed.

### Workflow Run

A durable record of a deployment, reset, destroy, reconcile, reporting, or validation workflow.

### Plugin

A versioned integration package exposing capabilities to the orchestration engine.

### Artifact

A stored object such as:

* generated OpenTofu plans
* Ansible inventories
* playbook output
* reports
* topology snapshots
* logs
* evidence
* screenshots
* environment attachments

### Audit Event

An immutable, timestamped event describing a meaningful action, authorization decision, or state transition.

---

## 8. Isolation and Topology Model

The topology engine has two primary views.

### Per-Environment Topology

A team or participant sees only its assigned environment instance, including:

* attacker or operator hosts
* target hosts
* internal networks
* sensors
* service health
* alerts
* objectives
* validation state
* score state
* compromised-host indicators

### Administrator Global Topology

Administrators can view:

* all environment instances
* shared services
* deployment status
* infrastructure health
* resource utilization
* aggregated alerts
* scoring comparisons
* plugin health
* platform events

Shared services may include:

* CTFd
* identity provider
* artifact storage
* reporting services
* centralized monitoring

Shared services must never create unintended lateral connectivity between isolated environments.

---

## 9. Declarative Environment Definitions

Environment definitions must be declarative.

They should describe desired outcomes and required capabilities, not imperative implementation steps.

Definitions may include:

* metadata
* teams
* topology
* subnets
* VM and container roles
* images
* firewall intent
* vulnerability packs
* objectives
* scoring or validation logic
* telemetry requirements
* monitoring requirements
* resource limits
* required plugins
* reset policy
* destroy policy

Example:

```yaml
apiVersion: controlplane.security/v1alpha1
kind: Environment
metadata:
  name: web-breach-101
  displayName: Web Breach 101

spec:
  teams:
    count: 2
    isolationPolicy: strict

  networks:
    - name: team-network
      cidrStrategy: per-team

  roles:
    - name: attacker
      image: kali-linux
    - name: web-server
      image: ubuntu-server

  vulnerabilityPacks:
    - weak-ssh
    - vulnerable-web-app

  telemetry:
    providers:
      - wazuh

  validation:
    provider: ctfd
    objectives:
      - gain-initial-access
      - retrieve-flag
      - submit-remediation-note

  requiredPlugins:
    - simulator
    - proxmox
    - wazuh
    - ctfd
```

The schema will evolve, but every breaking change must be versioned.

---

## 10. Vulnerability and Simulation Packs

Vulnerability packs are modular, reusable, versioned content packages.

Each pack should eventually include:

* metadata
* supported operating systems
* dependencies
* deployment playbooks
* cleanup playbooks
* validation checks
* detection logic
* scoring hooks
* documentation
* risk classification
* rollback guidance

Examples:

* Weak SSH
* Default Credentials
* Exposed SMB
* SQL Injection
* Cross-Site Scripting
* Log4Shell
* Misconfigured Active Directory
* Ransomware Simulation

Packs must never silently deploy outside an approved environment workflow.

---

## 11. Plugin Architecture

Every major external integration must be implemented as a plugin.

A plugin exposes only the capabilities it supports.

Baseline capability concepts:

* validate
* plan
* apply
* status
* reconcile
* reset
* destroy
* health
* discover
* collect-artifacts

Examples:

* Proxmox Plugin
* OpenTofu Runner Plugin
* Ansible Runner Plugin
* Wazuh Plugin
* CTFd Plugin
* Security Onion Plugin
* VMware Plugin
* AWS Plugin
* Notification Plugin

Plugins must be:

* independently versioned
* capability-aware
* observable
* testable in isolation
* replaceable
* minimally privileged
* configured through secure references instead of plaintext secrets

The first plugin is a Simulator Plugin.

The Simulator Plugin must follow the same contract as real infrastructure plugins while creating only simulated resources in PostgreSQL.

It is a reference implementation and test harness, not a disposable mock.

---

## 12. AI Architecture and Governance

AI is a first-class product capability, not unrestricted automation.

Approved AI use cases include:

* environment draft generation
* topology recommendations
* pack recommendations
* deployment-plan explanations
* infrastructure and configuration drafts
* attack-path summaries
* operator assistant support
* alert correlation
* after-action reports
* executive summaries
* policy-aware recommendations

AI must operate under these constraints:

1. AI-generated content is a draft until validated and approved.

2. AI cannot directly execute deployment, reset, destroy, credential, firewall, network, or privilege-changing actions.

3. AI tool access must be explicitly scoped.

4. AI actions and outputs must be logged.

5. AI-generated plans must identify assumptions and risk.

6. Human administrators approve production-impacting changes.

7. Declarative schemas, policy validation, and orchestration safeguards are authoritative—not model output.

---

## 13. Security Requirements

The platform coordinates security tooling and potentially dangerous workloads. Security controls are foundational.

Required principles:

* least privilege
* secrets never committed to source control
* organization and tenant isolation
* per-environment isolation
* strong RBAC
* immutable audit logging
* short-lived credentials where possible
* encrypted secrets at rest
* encrypted transport in production
* dependency scanning
* container scanning
* signed or verified plugin artifacts in later phases
* secure defaults
* explicit approval gates
* safe retry behavior
* no API-to-hypervisor direct execution
* no unrestricted shell execution from web requests
* clear separation between management plane and environment workloads

Environment workloads must not have unrestricted access to home, enterprise, management, or public networks unless explicitly permitted by a documented policy and approved deployment plan.

---

## 14. Data, State, and Observability

The platform must distinguish between:

* desired state
* planned state
* observed state
* workflow state
* topology state
* telemetry state
* score state
* validation state

PostgreSQL is the transactional system of record for the control plane.

Object storage is used for large artifacts, reports, plans, logs, and generated files.

The topology engine combines:

* declared environment intent
* deployed inventory
* plugin discovery
* health checks
* telemetry events
* validation events
* scoring events

The topology is not only a diagram. It is a live operational projection of the environment state.

---

## 15. Initial Technical Direction

Initial implementation direction:

* React + TypeScript frontend
* FastAPI backend
* Python worker services
* PostgreSQL
* Docker Compose for local development
* MinIO-compatible object storage
* OIDC-compatible identity provider
* Temporal or equivalent durable workflow engine
* OpenTofu as the initial IaC engine
* Ansible for configuration management
* React Flow for topology visualization
* Wazuh as the first blue-team integration
* CTFd as the first scoring integration
* Proxmox as the first real infrastructure provider

These are implementation choices, not permanent constraints. Changes affecting system boundaries require an ADR.

---

## 16. MVP Scope

The first production-oriented milestone is:

**SECP-001: Control Plane Foundation**

SECP-001 includes:

* monorepo foundation
* local development environment
* authentication foundation
* PostgreSQL data model
* environment templates and immutable versions
* deployment-plan generation
* explicit plan approval
* workflow boundary
* audit events
* simulator plugin
* two-team simulated environment execution
* topology UI
* reset and destroy workflows
* automated tests
* CI

SECP-001 explicitly excludes:

* real Proxmox provisioning
* OpenTofu apply
* Ansible execution
* real Kali deployment
* real vulnerable target deployment
* real Wazuh deployment
* real CTFd deployment
* AI copilot implementation
* cloud-provider support
* public multi-tenant hosting
* billing and commercial packaging

---

## 17. Future Milestone Direction

### SECP-002: Proxmox Foundation

* Proxmox plugin
* inventory discovery
* safe resource provisioning
* OpenTofu runner integration
* isolated network creation
* VM lifecycle support
* observed-state reconciliation

SECP-002 is delivered in safe sub-phases. This clarification adds detail only; it
does not remove or weaken any architectural invariant in §6.

* **SECP-002A — Provider safety, targets, inventory discovery, Temporal activation,
  address-space reservations.** Introduces organization-scoped, secret-free
  execution targets; provider-neutral observed inventory/topology; immutable
  provider inventory snapshots; transactional network/address-space reservations;
  worker-only secret resolution; activation of the durable Temporal path; and a
  **read-only** Proxmox plugin (validate/health/discover/status only). No real
  provisioning, mutation, or real-endpoint discovery occurs. See
  [`docs/architecture/secp-002a-proxmox-discovery.md`](architecture/secp-002a-proxmox-discovery.md)
  and ADR-006…010.
* **SECP-002B — Controlled provisioning.** Delivered in safe sub-phases:
  * **SECP-002B-0 — Provisioning safety harness + fake OpenTofu runner.** Immutable,
    secret-free provisioning manifests bound to an approved plan + pinned target;
    a strict blast-radius scope policy (allowlists/bounds, default-deny external
    connectivity); a worker-only `ProvisioningRunner` seam implemented **only** by a
    `FakeOpenTofuRunner` (no subprocess, network, provider client, or OpenTofu
    binary); and a durable provisioning-operation lifecycle. Target-bound deployment
    remains refused by default; the fake runner is reachable only behind an explicit
    dev/test gate with all preconditions met. **No real provisioning or
    infrastructure.** See
    [`docs/architecture/secp-002b-0-provisioning-safety.md`](architecture/secp-002b-0-provisioning-safety.md)
    and ADR-011/ADR-012.
  * **SECP-002B-1 — First disposable isolated Proxmox lab via worker-only OpenTofu.**
    A real, pinned OpenTofu runner behind the SECP-002B-0 seam and gate: isolated
    network creation and VM/container lifecycle on a disposable lab, all behind plan
    approval and worker-only execution.
* **SECP-002C — Reconciliation, reset/destroy, drift handling** against real
  infrastructure.

### SECP-003: Configuration and Content

* Ansible runner plugin
* Kali attacker role
* Ubuntu web-server role
* vulnerability and simulation pack framework
* baseline reset support
* artifact capture

### SECP-004: Detection and Validation

* Wazuh integration
* CTFd integration
* telemetry pipeline
* objectives
* validation events
* score events
* alert-to-topology overlays

### SECP-005: AI Copilot

* environment-authoring assistance
* deployment-plan explanation
* topology-generation assistance
* policy-aware recommendations
* reporting generation
* strict approval and audit controls

### SECP-006: Enterprise Readiness

* additional identity providers
* advanced RBAC
* high-availability design
* backup and restore
* plugin signing
* organization-isolation hardening
* cloud-provider plugins
* self-hosted and managed deployment models

---

## 18. Engineering Workflow

All changes follow this model:

1. Read this charter.
2. Review relevant ADRs.
3. Work in a feature branch.
4. Add or update tests.
5. Run local checks.
6. Open a pull request.
7. Require CI success.
8. Require human review for architecture, security, infrastructure, and destructive workflows.
9. Merge only after approval.

No developer, agent, automation, or workflow may bypass branch protections, approval gates, or test requirements.

---

## 19. Definition of Success

The platform succeeds when an organization can define a secure environment declaratively, approve a deterministic deployment plan, deploy isolated instances, observe them live, validate or score activity, reset or destroy them safely, and produce useful reports—without manually stitching together infrastructure, scripts, dashboards, and security tools.

The platform should feel like one coherent operational system, even though it orchestrates many underlying technologies.
