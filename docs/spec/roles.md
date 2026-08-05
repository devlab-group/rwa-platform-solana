# Role & mutability matrix

Solana has no `AccessControl` role registry. Each program stores its authorities as
single-holder pubkeys on its own state PDA (`rwa-compliance`'s `Registry`,
`rwa-supply-controller`/`rwa-vault`/`rwa-redemption`'s `Config`, `rwa-pricing`'s
`Strategy`), and every gated instruction requires the matching signer. A "role" is
therefore one pubkey per program, rotated by that program's admin.

| Authority             | Stored on                                | Powers                                                                     |
| --------------------- | ---------------------------------------- | -------------------------------------------------------------------------- |
| `admin`               | every program's state PDA                | rotate that program's authorities and mutable settings; two-step handover  |
| `pauser`              | `rwa-compliance` `Registry`              | pause/unpause the project (single project-wide emergency flag)             |
| `compliance_authority`| `rwa-compliance` `Registry`              | set wallet status/expiry                                                    |
| `pricer`              | `rwa-pricing` `Strategy`                 | update purchase/redemption prices                                          |
| `treasurer`           | `rwa-vault` `Config`, `rwa-redemption` `Config` | vault `withdraw_proceeds`; redemption `fund`                        |
| `redemption_manager`  | `rwa-redemption` `Config`                | redemption `reject`                                                        |
| `auditor_eth`         | `rwa-supply-controller` `Config`         | not a signer — the 20-byte secp256k1 address every attestation must recover to |

- Admin rotation is **two-step** on every program: `propose_admin` records
  `pending_admin`, and the proposed key must `accept_admin` itself. A zero pending admin
  is rejected. This is the Solana analogue of a default-admin delay: no single mistaken
  `set` can hand the project to an unreachable key.
- The auditor is stored authority in `rwa-supply-controller`, not a transaction-sending
  role. Changed by admin; `set_auditor` is immediate and single-signature, so hold admin
  behind a threshold multisig.
- `system_set` / `finalized` are one-way go-live latches, not roles: bootstrap pins the
  Vault + escrow authorities and the supply-controller/mint ids, then `finalize` verifies
  the cross-program wiring and flips the project live. Mint/burn are gated on `finalized`.
- The deployer keypair is the programs' **upgrade authority**, which is separate from every
  role above. Move it somewhere safer once the deployment is live.
