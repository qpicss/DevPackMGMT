# DevPackMGMT documentation

DevPackMGMT is an API management platform: providers publish APIs as products, developers get access for their applications, and gateways serve the traffic. This documentation is also in the console, under **Docs** in the menu.

## EU Digital Identity Wallet

Verify and issue EU Digital Identity Wallet credentials with a dedicated gateway. The business brings its certificates and its backend; the gateway does the wallet protocols and the cryptography, under the business's name.

| You want to | Product | Start here |
|---|---|---|
| **Check** credentials people show from their wallet: a diploma, identity, age | EU Wallet: Relying Party / Verifier | [Tutorial 9: Verify a diploma](tutorials/09-verify-a-diploma.md) |
| **Issue** your credentials into wallets: diplomas, badges, memberships | EU Wallet: Attestation Provider | [Tutorial 10: Issue diplomas](tutorials/10-issue-diplomas.md) |
| **Onboard customers** (KYC) with the PID: rules, form-data match, evidence for AML records | EU Wallet: Relying Party / Verifier with a KYC profile | [Tutorial 11: KYC with the PID](tutorials/11-kyc-with-the-pid.md) |
| Understand the offer, the diploma example and the five steps to run each | | [EU Wallet overview](eu-wallet.md) |
| Look up an operation, a check or a setting | | [EU Wallet gateways: reference](guides/eu-wallet-gateway.md) |

## Start with your role

| You are | You want to | Start here |
|---|---|---|
| **Developer or member** | Find APIs, create applications, get tokens and call APIs | [Guide for developers and members](users/developers.md), then [Tutorial 5](tutorials/05-call-an-api.md) |
| **Organization admin** | Publish APIs, run gateways, approve access, manage your team | [Guide for organization admins](users/org-admins.md), then [Tutorial 1](tutorials/01-publish-your-first-api.md) |
| **Site admin** | Run the platform: users, organizations, the server | [Guide for site admins](users/site-admins.md), then [Tutorial 8](tutorials/08-run-the-platform.md) |
| **Integrator** | Automate any of this | [API examples](guides/api-examples.md) and the [REST API reference](guides/api-reference.md) |

New to the platform? Read [Concepts](concepts.md) for how organizations, catalogs, products, applications and gateways fit together, and [Users and roles](users/README.md) for who can do what.

Running the console yourself? [Getting started](getting-started.md) installs it.

## Tutorials

The first seven build on each other: work through them in order the first time. Tutorials 9 and 10 stand on their own and can be read in either order; 11 builds on 9.

| | Tutorial | For |
|---|---|---|
| 1 | [Publish your first API](tutorials/01-publish-your-first-api.md): a catalog, an imported OpenAPI file, a published product | Org admins |
| 2 | [Design an API with the data dictionary](tutorials/02-design-with-the-dictionary.md): reusable fields and objects for parameters and bodies | Org admins |
| 3 | [Edit schemas in the schema designer](tutorials/03-edit-schemas.md): `components.schemas` as trees, bodies edited in place | Org admins |
| 4 | [Run a gateway](tutorials/04-run-a-gateway.md): a port, a Docker node, an attached catalog | Org admins |
| 5 | [Call an API as a developer](tutorials/05-call-an-api.md): an application, access, a token, a call | Developers |
| 6 | [Protect an API with a flow](tutorials/06-protect-an-api-with-a-flow.md): validation, threat protection, a script, the real backend | Org admins |
| 7 | [Work as a team](tutorials/07-work-as-a-team.md): invitations, roles, several organizations | Org admins, members |
| 8 | [Run the platform](tutorials/08-run-the-platform.md): onboard an organization, help from inside, handle account requests | Site admins |
| 9 | [Verify a diploma with the EU Wallet](tutorials/09-verify-a-diploma.md): a Verifier gateway and the employer's backend | Org admins, integrators |
| 10 | [Issue diplomas into the EU Wallet](tutorials/10-issue-diplomas.md): an Attestation Provider gateway and the university's backend | Org admins, integrators |
| 11 | [Onboard customers with KYC](tutorials/11-kyc-with-the-pid.md): a KYC profile on the PID, form-data matching and evidence | Org admins, integrators |

## Reference

**Users**

- [Users and roles](users/README.md): the kinds of users, what each role can do, and account options.
- [Developers and members](users/developers.md), [Organization admins](users/org-admins.md), [Site admins](users/site-admins.md): every page and option, by role.

**API**

- [Getting an access token](guides/access-tokens.md): where tokens come from, how to ask for one, and what to check when a call is refused.
- [REST API reference](guides/api-reference.md): every endpoint of the console.
- [API examples](guides/api-examples.md): end-to-end scripts, from publishing an API to calling it.
- [Managing people](guides/managing-people.md): site admins, org admins and members through the API.
- [EU Wallet gateways: reference](guides/eu-wallet-gateway.md): every wallet operation, check, reason code, setting and limit.

**Operating**

- [Configuration](guides/configuration.md): every environment variable of the console.
- [Operations](guides/operations.md): production setup, migrations, backups, certificates and upgrades.
- [Deploying to the cloud](guides/cloud-deployment.md): the plan of action for running the console and the gateways separately, with step-by-step guides and scripts for [AWS](guides/deploy-aws.md) and [Azure](guides/deploy-azure.md).
- [Installing without internet access](guides/offline-install.md): an offline bundle of the console for servers that can't reach the internet.
- [Running the console with Docker](guides/console-docker.md): the console and MySQL as containers, and moving a console with its data and certificates to another server.
- [Security](guides/security.md): authentication, tenancy, secrets and the browser.
- [Gateway reference](../gateway/README.md): node settings, Docker and systemd, policies, checking steps and error responses.
- [Development](guides/development.md): architecture, tests and conventions.

## Help inside the console

- **Docs** in the menu opens this documentation, with a link to the guide for your role.
- The **?** button in the header tours the page you're on. The dashboard offers the platform tour on your first visit. Press **Esc** to leave a tour, and the arrow keys to move through it.
