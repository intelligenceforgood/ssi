# SSI Developer & Admin Documentation

These docs target contributors, operators, and system administrators who **develop, deploy, and maintain** SSI.

For **end-user documentation** (how to use the CLI, write playbooks, interpret results), see the [SSI section of the docs site](../../docs/book/ssi/README.md).

## Contents

| Document                                       | Audience  | Description                                                                    |
| ---------------------------------------------- | --------- | ------------------------------------------------------------------------------ |
| [tdd.md](tdd.md)                               | Developer | Technical design: ADRs, component stack, data architecture, pipeline, security |
| [developer_guide.md](developer_guide.md)       | Developer | Environment setup, project structure, testing, Docker, GCP deployment          |
| [api_reference.md](api_reference.md)           | Developer | REST API endpoint contracts with request/response schemas                      |
| [playbook_authoring.md](playbook_authoring.md) | Developer | Detailed JSON schema reference, template variables, testing workflow           |
| [batch_scheduling.md](batch_scheduling.md)     | Operator  | Campaign runner, Cloud Run Jobs, Cloud Scheduler, cost/concurrency sizing      |
