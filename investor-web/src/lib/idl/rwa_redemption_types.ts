/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/rwa_redemption.json`.
 */
export type RwaRedemption = {
  "address": "32J24AMuuocveSVofvbqWS4HrspAKqsNp7xnrtWw1uFY",
  "metadata": {
    "name": "rwaRedemption",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Redemption request->fund->claim state machine (RedemptionEscrow.sol on Solana)"
  },
  "instructions": [
    {
      "name": "acceptAdmin",
      "docs": [
        "Two-step admin rotation (accept)."
      ],
      "discriminator": [
        112,
        42,
        45,
        90,
        116,
        181,
        13,
        170
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "newAdmin",
          "signer": true
        }
      ],
      "args": []
    },
    {
      "name": "cancelAdminTransfer",
      "docs": [
        "Withdraw a pending admin transfer (current admin only)."
      ],
      "discriminator": [
        38,
        131,
        157,
        31,
        240,
        137,
        44,
        215
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "signer": true,
          "relations": [
            "config"
          ]
        }
      ],
      "args": []
    },
    {
      "name": "cancelRedemption",
      "docs": [
        "No `!paused` guard (deliberate) — the escrow-only hook bypass lets this",
        "complete during an emergency pause. Beneficiary must still be allowed."
      ],
      "discriminator": [
        197,
        243,
        101,
        86,
        2,
        37,
        105,
        106
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "request",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "id"
              }
            ]
          }
        },
        {
          "name": "rwaMint",
          "docs": [
            "Read-only (see `RequestRedemption`)."
          ]
        },
        {
          "name": "escrowToken",
          "docs": [
            "Pinned to the canonical escrow ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "beneficiaryToken",
          "writable": true
        },
        {
          "name": "beneficiaryRecord"
        },
        {
          "name": "beneficiary",
          "signer": true
        },
        {
          "name": "rwaTokenProgram",
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
      ],
      "args": [
        {
          "name": "id",
          "type": "u64"
        }
      ]
    },
    {
      "name": "claimRedemption",
      "docs": [
        "Permissionless. Keeps its `!paused` guard; never re-checks compliance."
      ],
      "discriminator": [
        109,
        110,
        9,
        188,
        195,
        217,
        112,
        83
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "request",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "id"
              }
            ]
          }
        },
        {
          "name": "rwaMint",
          "docs": [
            "Read-only (see `RequestRedemption`)."
          ]
        },
        {
          "name": "quoteMint"
        },
        {
          "name": "escrowToken",
          "docs": [
            "Pinned to the canonical escrow ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "escrowQuote",
          "docs": [
            "Pinned to the canonical escrow-quote ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "vaultToken",
          "docs": [
            "Vault inventory account — RWA returns here. Pinned to the canonical",
            "inventory ATA of the pinned vault authority."
          ],
          "writable": true
        },
        {
          "name": "beneficiaryQuote",
          "writable": true
        },
        {
          "name": "rwaTokenProgram",
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        },
        {
          "name": "quoteTokenProgram",
          "docs": [
            "Pinned to the quote mint's own owning program."
          ]
        }
      ],
      "args": [
        {
          "name": "id",
          "type": "u64"
        }
      ]
    },
    {
      "name": "closeRequest",
      "docs": [
        "Reclaim the rent of a request that has reached a terminal state",
        "(`Completed` / `Rejected` / `Cancelled`), returning the lamports to the",
        "beneficiary who paid for it. Request PDAs are seeded on a monotonic counter,",
        "so a closed id is never reused — closing introduces no replay surface.",
        "Permissionless: the only effect is refunding rent to the recorded",
        "beneficiary, and a still-open request is rejected by the status check."
      ],
      "discriminator": [
        170,
        46,
        165,
        120,
        223,
        102,
        115,
        2
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "request",
          "docs": [
            "Refunds rent to `beneficiary`, which must be the request's recorded",
            "beneficiary (the original rent payer)."
          ],
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "id"
              }
            ]
          }
        },
        {
          "name": "beneficiary",
          "writable": true,
          "relations": [
            "request"
          ]
        }
      ],
      "args": [
        {
          "name": "id",
          "type": "u64"
        }
      ]
    },
    {
      "name": "fundRedemption",
      "discriminator": [
        63,
        242,
        144,
        13,
        107,
        199,
        16,
        159
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "request",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "id"
              }
            ]
          }
        },
        {
          "name": "quoteMint"
        },
        {
          "name": "treasurer",
          "signer": true,
          "relations": [
            "config"
          ]
        },
        {
          "name": "treasurerQuote",
          "writable": true
        },
        {
          "name": "escrowQuote",
          "docs": [
            "Pinned to the canonical escrow-quote ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "beneficiaryRecord"
        },
        {
          "name": "quoteTokenProgram",
          "docs": [
            "Pinned to the quote mint's own owning program."
          ]
        }
      ],
      "args": [
        {
          "name": "id",
          "type": "u64"
        }
      ]
    },
    {
      "name": "initialize",
      "discriminator": [
        175,
        175,
        109,
        31,
        13,
        152,
        155,
        237
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "rwaMint"
        },
        {
          "name": "quoteMint"
        },
        {
          "name": "strategy",
          "docs": [
            "Pinned to the canonical pricing `Strategy` PDA."
          ],
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  116,
                  114,
                  97,
                  116,
                  101,
                  103,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                150,
                133,
                68,
                88,
                241,
                156,
                178,
                8,
                111,
                7,
                97,
                220,
                183,
                189,
                69,
                121,
                119,
                234,
                187,
                95,
                78,
                249,
                147,
                133,
                96,
                67,
                50,
                210,
                81,
                167,
                79,
                112
              ]
            }
          }
        },
        {
          "name": "registry"
        },
        {
          "name": "payer",
          "writable": true,
          "signer": true
        },
        {
          "name": "program",
          "address": "32J24AMuuocveSVofvbqWS4HrspAKqsNp7xnrtWw1uFY"
        },
        {
          "name": "programData"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "admin",
          "type": "pubkey"
        },
        {
          "name": "treasurer",
          "type": "pubkey"
        },
        {
          "name": "redemptionManager",
          "type": "pubkey"
        },
        {
          "name": "vaultAuthority",
          "type": "pubkey"
        },
        {
          "name": "redemptionTimeout",
          "type": "u64"
        },
        {
          "name": "quoteDecimals",
          "type": "u8"
        }
      ]
    },
    {
      "name": "proposeAdmin",
      "docs": [
        "Two-step admin rotation (propose). Rejects a zero pending admin",
        "and emits the proposal."
      ],
      "discriminator": [
        121,
        214,
        199,
        212,
        87,
        39,
        117,
        234
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "signer": true,
          "relations": [
            "config"
          ]
        }
      ],
      "args": [
        {
          "name": "newAdmin",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "rejectRedemption",
      "discriminator": [
        137,
        154,
        82,
        200,
        41,
        45,
        174,
        61
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "request",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "arg",
                "path": "id"
              }
            ]
          }
        },
        {
          "name": "rwaMint",
          "docs": [
            "Read-only (see `RequestRedemption`)."
          ]
        },
        {
          "name": "escrowToken",
          "docs": [
            "Pinned to the canonical escrow ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "beneficiaryToken",
          "writable": true
        },
        {
          "name": "beneficiaryRecord"
        },
        {
          "name": "redemptionManager",
          "signer": true,
          "relations": [
            "config"
          ]
        },
        {
          "name": "rwaTokenProgram",
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
      ],
      "args": [
        {
          "name": "id",
          "type": "u64"
        },
        {
          "name": "reasonCode",
          "type": {
            "array": [
              "u8",
              32
            ]
          }
        }
      ]
    },
    {
      "name": "requestRedemption",
      "discriminator": [
        14,
        62,
        182,
        237,
        59,
        79,
        149,
        22
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "registry",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  103,
                  105,
                  115,
                  116,
                  114,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                196,
                11,
                7,
                132,
                28,
                242,
                159,
                208,
                109,
                62,
                38,
                181,
                145,
                168,
                249,
                249,
                115,
                87,
                84,
                27,
                119,
                113,
                187,
                186,
                199,
                34,
                34,
                134,
                224,
                237,
                212,
                96
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "strategy",
          "docs": [
            "Pinned to the canonical pricing `Strategy` PDA."
          ],
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  115,
                  116,
                  114,
                  97,
                  116,
                  101,
                  103,
                  121
                ]
              }
            ],
            "program": {
              "kind": "const",
              "value": [
                150,
                133,
                68,
                88,
                241,
                156,
                178,
                8,
                111,
                7,
                97,
                220,
                183,
                189,
                69,
                121,
                119,
                234,
                187,
                95,
                78,
                249,
                147,
                133,
                96,
                67,
                50,
                210,
                81,
                167,
                79,
                112
              ]
            }
          },
          "relations": [
            "config"
          ]
        },
        {
          "name": "rwaMint",
          "docs": [
            "Read-only — `transfer_checked` takes the mint read-only, so a write",
            "lock here would needlessly serialize every redemption against the mint."
          ]
        },
        {
          "name": "request",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  113,
                  117,
                  101,
                  115,
                  116
                ]
              },
              {
                "kind": "account",
                "path": "config.nextId",
                "account": "config"
              }
            ]
          }
        },
        {
          "name": "beneficiary",
          "writable": true,
          "signer": true
        },
        {
          "name": "beneficiaryToken",
          "writable": true
        },
        {
          "name": "escrowToken",
          "docs": [
            "Pinned to the canonical escrow ATA of the redemption PDA."
          ],
          "writable": true
        },
        {
          "name": "beneficiaryRecord"
        },
        {
          "name": "rwaTokenProgram",
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        },
        {
          "name": "systemProgram",
          "address": "11111111111111111111111111111111"
        }
      ],
      "args": [
        {
          "name": "rwaAmount",
          "type": "u64"
        },
        {
          "name": "minQuoteOut",
          "type": "u64"
        },
        {
          "name": "deadline",
          "type": "u64"
        }
      ]
    },
    {
      "name": "setRedemptionManager",
      "docs": [
        "Rotate the redemption manager."
      ],
      "discriminator": [
        14,
        173,
        148,
        95,
        82,
        64,
        180,
        187
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "signer": true,
          "relations": [
            "config"
          ]
        }
      ],
      "args": [
        {
          "name": "newManager",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "setTreasurer",
      "docs": [
        "Rotate the treasurer."
      ],
      "discriminator": [
        100,
        87,
        30,
        190,
        191,
        14,
        164,
        98
      ],
      "accounts": [
        {
          "name": "config",
          "writable": true,
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  114,
                  101,
                  100,
                  101,
                  109,
                  112,
                  116,
                  105,
                  111,
                  110,
                  45,
                  99,
                  111,
                  110,
                  102,
                  105,
                  103
                ]
              }
            ]
          }
        },
        {
          "name": "admin",
          "signer": true,
          "relations": [
            "config"
          ]
        }
      ],
      "args": [
        {
          "name": "newTreasurer",
          "type": "pubkey"
        }
      ]
    }
  ],
  "accounts": [
    {
      "name": "config",
      "discriminator": [
        155,
        12,
        170,
        224,
        30,
        250,
        204,
        130
      ]
    },
    {
      "name": "redemptionRequest",
      "discriminator": [
        117,
        157,
        214,
        214,
        64,
        160,
        31,
        58
      ]
    }
  ],
  "events": [
    {
      "name": "adminChanged",
      "discriminator": [
        232,
        34,
        31,
        226,
        62,
        18,
        19,
        114
      ]
    },
    {
      "name": "adminProposed",
      "discriminator": [
        129,
        249,
        226,
        227,
        199,
        82,
        110,
        243
      ]
    },
    {
      "name": "adminTransferCancelled",
      "discriminator": [
        93,
        23,
        69,
        55,
        216,
        128,
        106,
        56
      ]
    },
    {
      "name": "redemptionCancelled",
      "discriminator": [
        22,
        106,
        118,
        26,
        83,
        110,
        71,
        174
      ]
    },
    {
      "name": "redemptionCompleted",
      "discriminator": [
        46,
        189,
        147,
        218,
        232,
        71,
        143,
        119
      ]
    },
    {
      "name": "redemptionFunded",
      "discriminator": [
        146,
        26,
        237,
        133,
        155,
        44,
        150,
        215
      ]
    },
    {
      "name": "redemptionRejected",
      "discriminator": [
        54,
        77,
        16,
        124,
        240,
        23,
        1,
        53
      ]
    },
    {
      "name": "redemptionRequested",
      "discriminator": [
        245,
        155,
        98,
        131,
        210,
        25,
        137,
        146
      ]
    },
    {
      "name": "requestClosed",
      "discriminator": [
        59,
        172,
        99,
        75,
        9,
        19,
        226,
        188
      ]
    },
    {
      "name": "roleChanged",
      "discriminator": [
        85,
        88,
        130,
        5,
        125,
        143,
        206,
        240
      ]
    }
  ],
  "errors": [
    {
      "code": 6000,
      "name": "zeroAddress",
      "msg": "zero address"
    },
    {
      "code": 6001,
      "name": "projectPaused",
      "msg": "project is paused"
    },
    {
      "code": 6002,
      "name": "callerNotAllowed",
      "msg": "caller is not allowed"
    },
    {
      "code": 6003,
      "name": "beneficiaryNotAllowed",
      "msg": "beneficiary is not allowed"
    },
    {
      "code": 6004,
      "name": "zeroAmount",
      "msg": "amount must be non-zero"
    },
    {
      "code": 6005,
      "name": "deadlineExpired",
      "msg": "deadline expired"
    },
    {
      "code": 6006,
      "name": "zeroQuote",
      "msg": "quote is zero"
    },
    {
      "code": 6007,
      "name": "quoteBelowMin",
      "msg": "quote below min"
    },
    {
      "code": 6008,
      "name": "zeroReasonCode",
      "msg": "reason code must be non-zero"
    },
    {
      "code": 6009,
      "name": "notPending",
      "msg": "request is not pending"
    },
    {
      "code": 6010,
      "name": "notFunded",
      "msg": "request is not funded"
    },
    {
      "code": 6011,
      "name": "notBeneficiary",
      "msg": "caller is not the beneficiary"
    },
    {
      "code": 6012,
      "name": "timeoutNotReached",
      "msg": "redemption timeout not reached"
    },
    {
      "code": 6013,
      "name": "quoteDeltaMismatch",
      "msg": "quote delta mismatch"
    },
    {
      "code": 6014,
      "name": "pricingFailed",
      "msg": "pricing failed"
    },
    {
      "code": 6015,
      "name": "overflow",
      "msg": "id overflow"
    },
    {
      "code": 6016,
      "name": "badStatus",
      "msg": "bad status byte"
    },
    {
      "code": 6017,
      "name": "invalidTimeout",
      "msg": "redemption timeout must be within [1 day, 365 days]"
    },
    {
      "code": 6018,
      "name": "requestNotTerminal",
      "msg": "request is not in a terminal state"
    },
    {
      "code": 6019,
      "name": "recordMismatch",
      "msg": "compliance record account does not match its owner"
    },
    {
      "code": 6020,
      "name": "wrongRegistry",
      "msg": "wrong registry account"
    },
    {
      "code": 6021,
      "name": "wrongStrategy",
      "msg": "wrong strategy account"
    },
    {
      "code": 6022,
      "name": "wrongMint",
      "msg": "wrong mint account"
    },
    {
      "code": 6023,
      "name": "notTreasurer",
      "msg": "caller is not the treasurer"
    },
    {
      "code": 6024,
      "name": "notRedemptionManager",
      "msg": "caller is not the redemption manager"
    },
    {
      "code": 6025,
      "name": "notAdmin",
      "msg": "caller is not the admin"
    },
    {
      "code": 6026,
      "name": "notPendingAdmin",
      "msg": "caller is not the pending admin"
    },
    {
      "code": 6027,
      "name": "noPendingAdmin",
      "msg": "no pending admin transfer to accept"
    },
    {
      "code": 6028,
      "name": "notUpgradeAuthority",
      "msg": "caller is not the program upgrade authority"
    },
    {
      "code": 6029,
      "name": "notFinalized",
      "msg": "deployment is not finalized"
    },
    {
      "code": 6030,
      "name": "unsafeMint",
      "msg": "configured RWA mint is unsafe (not Token-2022 / wrong hook / disallowed extension)"
    },
    {
      "code": 6031,
      "name": "unsafeQuoteMint",
      "msg": "configured quote mint is unsafe (wrong program / disallowed extension)"
    },
    {
      "code": 6032,
      "name": "mintQuoteSame",
      "msg": "RWA mint and quote mint must be different"
    },
    {
      "code": 6033,
      "name": "notCanonicalAta",
      "msg": "token account is not the canonical ATA"
    },
    {
      "code": 6034,
      "name": "wrongTokenProgram",
      "msg": "wrong token program for the RWA leg"
    },
    {
      "code": 6035,
      "name": "decimalsMismatch",
      "msg": "pricing decimals do not match the RWA mint"
    },
    {
      "code": 6036,
      "name": "quoteDecimalsMismatch",
      "msg": "quote mint decimals do not match the configured price scale"
    },
    {
      "code": 6037,
      "name": "rwaDeltaMismatch",
      "msg": "RWA transfer delta mismatch"
    }
  ],
  "types": [
    {
      "name": "adminChanged",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "previous",
            "type": "pubkey"
          },
          {
            "name": "newAdmin",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "adminProposed",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "newAdmin",
            "type": "pubkey"
          },
          {
            "name": "by",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "adminTransferCancelled",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "cancelled",
            "type": "pubkey"
          },
          {
            "name": "by",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "config",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "admin",
            "type": "pubkey"
          },
          {
            "name": "pendingAdmin",
            "type": "pubkey"
          },
          {
            "name": "treasurer",
            "type": "pubkey"
          },
          {
            "name": "redemptionManager",
            "type": "pubkey"
          },
          {
            "name": "vault",
            "type": "pubkey"
          },
          {
            "name": "rwaMint",
            "type": "pubkey"
          },
          {
            "name": "quoteMint",
            "type": "pubkey"
          },
          {
            "name": "quoteDecimals",
            "docs": [
              "The quote mint's decimals, bound at `initialize` to the price scale."
            ],
            "type": "u8"
          },
          {
            "name": "strategy",
            "type": "pubkey"
          },
          {
            "name": "registry",
            "type": "pubkey"
          },
          {
            "name": "redemptionTimeout",
            "type": "u64"
          },
          {
            "name": "nextId",
            "type": "u64"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "redemptionCancelled",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "beneficiary",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "redemptionCompleted",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "beneficiary",
            "type": "pubkey"
          },
          {
            "name": "rwaAmount",
            "type": "u64"
          },
          {
            "name": "quoteAmount",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "redemptionFunded",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "funder",
            "type": "pubkey"
          },
          {
            "name": "quoteAmount",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "redemptionRejected",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "reasonCode",
            "type": {
              "array": [
                "u8",
                32
              ]
            }
          },
          {
            "name": "by",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "redemptionRequest",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "beneficiary",
            "type": "pubkey"
          },
          {
            "name": "rwaAmount",
            "type": "u64"
          },
          {
            "name": "quoteAmount",
            "type": "u64"
          },
          {
            "name": "createdAt",
            "type": "u64"
          },
          {
            "name": "status",
            "docs": [
              "redemption_core::RedemptionStatus as u8."
            ],
            "type": "u8"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "redemptionRequested",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "beneficiary",
            "type": "pubkey"
          },
          {
            "name": "rwaAmount",
            "type": "u64"
          },
          {
            "name": "quoteAmount",
            "type": "u64"
          },
          {
            "name": "createdAt",
            "type": "u64"
          }
        ]
      }
    },
    {
      "name": "registry",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "admin",
            "type": "pubkey"
          },
          {
            "name": "pendingAdmin",
            "type": "pubkey"
          },
          {
            "name": "complianceAuthority",
            "type": "pubkey"
          },
          {
            "name": "pauser",
            "type": "pubkey"
          },
          {
            "name": "vault",
            "type": "pubkey"
          },
          {
            "name": "escrow",
            "type": "pubkey"
          },
          {
            "name": "supplyController",
            "docs": [
              "Supply-controller program id, pinned at `set_system_addresses`; the",
              "authority behind the `finalize` CPI that flips `finalized`."
            ],
            "type": "pubkey"
          },
          {
            "name": "rwaMint",
            "docs": [
              "The RWA mint, pinned at `set_system_addresses`. The transfer hook —",
              "the single compliance chokepoint — asserts the mint it is invoked for equals",
              "this, so the guarantee no longer depends only on the handler being",
              "side-effect-free for a foreign mint that points its hook extension here."
            ],
            "type": "pubkey"
          },
          {
            "name": "systemSet",
            "type": "bool"
          },
          {
            "name": "paused",
            "type": "bool"
          },
          {
            "name": "finalized",
            "docs": [
              "Global go-live flag; set once cross-program wiring is verified."
            ],
            "type": "bool"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "requestClosed",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "id",
            "type": "u64"
          },
          {
            "name": "beneficiary",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "roleChanged",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "role",
            "type": "u8"
          },
          {
            "name": "previous",
            "type": "pubkey"
          },
          {
            "name": "newValue",
            "type": "pubkey"
          },
          {
            "name": "by",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "strategy",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "admin",
            "type": "pubkey"
          },
          {
            "name": "pendingAdmin",
            "type": "pubkey"
          },
          {
            "name": "pricer",
            "type": "pubkey"
          },
          {
            "name": "tokenDecimals",
            "type": "u8"
          },
          {
            "name": "purchasePrice",
            "type": "u64"
          },
          {
            "name": "redemptionPrice",
            "type": "u64"
          },
          {
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    }
  ]
};
