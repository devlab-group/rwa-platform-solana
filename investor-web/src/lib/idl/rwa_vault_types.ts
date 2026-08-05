/**
 * Program IDL in camelCase format in order to be used in JS/TS.
 *
 * Note that this is only a type helper and is not the actual IDL. The original
 * IDL can be found at `target/idl/rwa_vault.json`.
 */
export type RwaVault = {
  "address": "2XnocgeBA5iT4mUEvuMCkbNPBscs9n7A2MdYL2zPBVjT",
  "metadata": {
    "name": "rwaVault",
    "version": "0.1.0",
    "spec": "0.1.0",
    "description": "Inventory + on-chain buy + withdraw proceeds (Vault.sol on Solana)"
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
      "name": "buy",
      "discriminator": [
        102,
        6,
        61,
        18,
        1,
        218,
        235,
        234
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  118,
                  97,
                  117,
                  108,
                  116,
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
            "lock would needlessly serialize every buy against the mint."
          ]
        },
        {
          "name": "quoteMint"
        },
        {
          "name": "vaultToken",
          "docs": [
            "Pinned to the canonical inventory ATA of the vault PDA."
          ],
          "writable": true
        },
        {
          "name": "vaultQuote",
          "docs": [
            "Pinned to the canonical quote-proceeds ATA of the vault PDA."
          ],
          "writable": true
        },
        {
          "name": "buyer",
          "signer": true
        },
        {
          "name": "buyerQuote",
          "writable": true
        },
        {
          "name": "recipientToken",
          "writable": true
        },
        {
          "name": "buyerRecord"
        },
        {
          "name": "recipientRecord"
        },
        {
          "name": "quoteTokenProgram",
          "docs": [
            "Pinned to the quote mint's own owning program, consistent with the",
            "`rwa_token_program` pin. (The quote ATA addresses are derived from this",
            "owner, so a mismatch already fails closed; this makes it explicit.)"
          ]
        },
        {
          "name": "rwaTokenProgram",
          "docs": [
            "Token-2022); further validated by invoke."
          ],
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
      ],
      "args": [
        {
          "name": "tokenAmount",
          "type": "u64"
        },
        {
          "name": "maxQuoteAmount",
          "type": "u64"
        },
        {
          "name": "deadline",
          "type": "u64"
        }
      ]
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
      "name": "controllerBurn",
      "docs": [
        "Burn inventory on behalf of the supply controller. The",
        "Vault PDA owns the inventory account, so only it can sign the Token-2022",
        "burn; the caller must be the stored supply-controller PDA (a signer via",
        "CPI seeds). This replaces a standing unlimited burn delegate."
      ],
      "discriminator": [
        70,
        145,
        171,
        161,
        63,
        244,
        162,
        39
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  118,
                  97,
                  117,
                  108,
                  116,
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
          "name": "mint",
          "writable": true
        },
        {
          "name": "vaultToken",
          "docs": [
            "Pinned to the canonical inventory ATA of the vault PDA."
          ],
          "writable": true
        },
        {
          "name": "supplyController",
          "docs": [
            "The supply-controller config PDA, signing via CPI seeds."
          ],
          "signer": true
        },
        {
          "name": "tokenProgram",
          "docs": [
            "The RWA leg is always Token-2022; pin the program so the hand-built",
            "permissioned-burn CPI can never be delivered to a substituted program."
          ],
          "address": "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"
        }
      ],
      "args": [
        {
          "name": "amount",
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
          "address": "2XnocgeBA5iT4mUEvuMCkbNPBscs9n7A2MdYL2zPBVjT"
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
          "name": "treasury",
          "type": "pubkey"
        },
        {
          "name": "supplyController",
          "type": "pubkey"
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
        "Two-step admin rotation (propose). Rejects a zero pending admin and emits",
        "the proposal."
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
    },
    {
      "name": "setTreasury",
      "discriminator": [
        57,
        97,
        196,
        95,
        195,
        206,
        106,
        136
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
                  118,
                  97,
                  117,
                  108,
                  116,
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
          "name": "newTreasury",
          "type": "pubkey"
        }
      ]
    },
    {
      "name": "withdrawProceeds",
      "discriminator": [
        124,
        68,
        215,
        12,
        201,
        136,
        54,
        72
      ],
      "accounts": [
        {
          "name": "config",
          "pda": {
            "seeds": [
              {
                "kind": "const",
                "value": [
                  118,
                  97,
                  117,
                  108,
                  116,
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
          "name": "quoteMint"
        },
        {
          "name": "vaultQuote",
          "docs": [
            "Pinned to the canonical quote-proceeds ATA of the vault PDA."
          ],
          "writable": true
        },
        {
          "name": "treasuryQuote",
          "docs": [
            "Proceeds land in the treasury's canonical ATA, not any account it owns."
          ],
          "writable": true
        },
        {
          "name": "treasurer",
          "signer": true,
          "relations": [
            "config"
          ]
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
          "name": "amount",
          "type": "u64"
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
      "name": "proceedsWithdrawn",
      "discriminator": [
        39,
        167,
        165,
        1,
        8,
        206,
        214,
        13
      ]
    },
    {
      "name": "purchased",
      "discriminator": [
        20,
        112,
        33,
        232,
        177,
        248,
        215,
        233
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
      "name": "deadlineExpired",
      "msg": "deadline expired"
    },
    {
      "code": 6003,
      "name": "zeroAmount",
      "msg": "amount must be non-zero"
    },
    {
      "code": 6004,
      "name": "callerNotAllowed",
      "msg": "buyer is not allowed"
    },
    {
      "code": 6005,
      "name": "recipientNotAllowed",
      "msg": "recipient is not allowed"
    },
    {
      "code": 6006,
      "name": "insufficientInventory",
      "msg": "insufficient inventory"
    },
    {
      "code": 6007,
      "name": "quoteAboveMax",
      "msg": "quote above max"
    },
    {
      "code": 6008,
      "name": "quoteDeltaMismatch",
      "msg": "quote delta mismatch"
    },
    {
      "code": 6009,
      "name": "pricingFailed",
      "msg": "pricing failed"
    },
    {
      "code": 6010,
      "name": "recordMismatch",
      "msg": "compliance record account does not match its owner"
    },
    {
      "code": 6011,
      "name": "wrongRegistry",
      "msg": "wrong registry account"
    },
    {
      "code": 6012,
      "name": "wrongStrategy",
      "msg": "wrong strategy account"
    },
    {
      "code": 6013,
      "name": "wrongMint",
      "msg": "wrong mint account"
    },
    {
      "code": 6014,
      "name": "notTreasurer",
      "msg": "caller is not the treasurer"
    },
    {
      "code": 6015,
      "name": "notAdmin",
      "msg": "caller is not the admin"
    },
    {
      "code": 6016,
      "name": "notPendingAdmin",
      "msg": "caller is not the pending admin"
    },
    {
      "code": 6017,
      "name": "noPendingAdmin",
      "msg": "no pending admin transfer to accept"
    },
    {
      "code": 6018,
      "name": "notSupplyController",
      "msg": "caller is not the authorized supply controller"
    },
    {
      "code": 6019,
      "name": "notUpgradeAuthority",
      "msg": "caller is not the program upgrade authority"
    },
    {
      "code": 6020,
      "name": "notFinalized",
      "msg": "deployment is not finalized"
    },
    {
      "code": 6021,
      "name": "unsafeMint",
      "msg": "configured RWA mint is unsafe (not Token-2022 / wrong hook / disallowed extension)"
    },
    {
      "code": 6022,
      "name": "unsafeQuoteMint",
      "msg": "configured quote mint is unsafe (wrong program / disallowed extension)"
    },
    {
      "code": 6023,
      "name": "mintQuoteSame",
      "msg": "RWA mint and quote mint must be different"
    },
    {
      "code": 6024,
      "name": "notCanonicalAta",
      "msg": "token account is not the canonical ATA"
    },
    {
      "code": 6025,
      "name": "wrongTokenProgram",
      "msg": "wrong token program for the RWA leg"
    },
    {
      "code": 6026,
      "name": "decimalsMismatch",
      "msg": "pricing decimals do not match the RWA mint"
    },
    {
      "code": 6027,
      "name": "quoteDecimalsMismatch",
      "msg": "quote mint decimals do not match the configured price scale"
    },
    {
      "code": 6028,
      "name": "selfTransfer",
      "msg": "recipient RWA account must not be the vault inventory account"
    },
    {
      "code": 6029,
      "name": "rwaDeltaMismatch",
      "msg": "RWA transfer delta mismatch"
    },
    {
      "code": 6030,
      "name": "burnDeltaMismatch",
      "msg": "burn delta mismatch"
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
            "name": "treasury",
            "type": "pubkey"
          },
          {
            "name": "supplyController",
            "docs": [
              "supply-controller config PDA allowed to call `controller_burn`."
            ],
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
              "the quote mint's decimals, bound at `initialize` to the price scale."
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
            "name": "bump",
            "type": "u8"
          }
        ]
      }
    },
    {
      "name": "proceedsWithdrawn",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "treasury",
            "type": "pubkey"
          },
          {
            "name": "amount",
            "type": "u64"
          },
          {
            "name": "by",
            "type": "pubkey"
          }
        ]
      }
    },
    {
      "name": "purchased",
      "type": {
        "kind": "struct",
        "fields": [
          {
            "name": "buyer",
            "type": "pubkey"
          },
          {
            "name": "recipient",
            "type": "pubkey"
          },
          {
            "name": "tokenAmount",
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
