# Based on EIP-2335 JSON Schema on https://eips.ethereum.org/EIPS/eip-2335#json-schema
KEYSTORE_JSON_SCHEMA = {
  "$ref": "#/definitions/Keystore",
  "definitions": {
    "Keystore": {
      "type": "object",
      "properties": {
        "crypto": {
          "type": "object",
          "properties": {
            "kdf": {
              "type": "object",
              "required": ["function", "params", "message"],
              "properties": {
                "function": {
                  "enum": ["pbkdf2", "scrypt"]
                },
                "params": {
                  "type": "object"
                },
                "message": {
                  "const": ""
                }
              },
              "allOf": [
                {
                  "if": {
                    "properties": {"function": {"const": "pbkdf2"}},
                    "required": ["function"]
                  },
                  "then": {
                    "properties": {
                      "params": {
                        "type": "object",
                        "properties": {
                          "dklen": {"const": 32},
                          "c": {"type": "integer", "minimum": 1},
                          "prf": {"const": "hmac-sha256"},
                          "salt": {
                            "type": "string",
                            "pattern": "^[0-9a-fA-F]{2,}$"
                          }
                        },
                        "required": ["dklen", "c", "prf", "salt"],
                        "additionalProperties": False
                      }
                    },
                    "required": ["params"]
                  }
                },
                {
                  "if": {
                    "properties": {"function": {"const": "scrypt"}},
                    "required": ["function"]
                  },
                  "then": {
                    "properties": {
                      "params": {
                        "type": "object",
                        "properties": {
                          "dklen": {"const": 32},
                          "n": {"type": "integer", "minimum": 1},
                          "p": {"type": "integer", "minimum": 1},
                          "r": {"type": "integer", "minimum": 1},
                          "salt": {
                            "type": "string",
                            "pattern": "^[0-9a-fA-F]{2,}$"
                          }
                        },
                        "required": ["dklen", "n", "p", "r", "salt"],
                        "additionalProperties": False
                      }
                    },
                    "required": ["params"]
                  }
                }
              ],
              "additionalProperties": False
            },
            "checksum": {
              "type": "object",
              "required": ["function", "params", "message"],
              "properties": {
                "function": {
                  "const": "sha256"
                },
                "params": {
                  "type": "object",
                  "additionalProperties": False
                },
                "message": {
                  "type": "string",
                  "pattern": "^[0-9a-fA-F]{64}$",
                  "description": "64-character lowercase hex string (SHA-256 digest)"
                }
              },
              "additionalProperties": False
            },
            "cipher": {
              "type": "object",
              "required": ["function", "params", "message"],
              "properties": {
                "function": {
                  "const": "aes-128-ctr"
                },
                "params": {
                  "type": "object",
                  "properties": {
                    "iv": {
                      "type": "string",
                      "pattern": "^[0-9a-fA-F]{32}$",
                      "description": "32-character lowercase hex string (16-byte IV)"
                    }
                  },
                  "required": ["iv"],
                  "additionalProperties": False
                },
                "message": {
                  "type": "string",
                  "pattern": "^[0-9a-fA-F]{64}$",
                  "description": "64-character lowercase hex string (encrypted data fragment)"
                }
              },
              "additionalProperties": False
            }
          },
          "required": ["kdf", "checksum", "cipher"],
          "additionalProperties": False
        },
        "description": {
          "type": "string"
        },
        "pubkey": {
          "type": "string",
          "pattern": "^[0-9a-fA-F]{96}$",
          "description": "96-character lowercase hex string (48-byte BLS public key)"
        },
        "path": {
          "type": "string",
          "pattern": "^m/[0-9]+(/[0-9]+)+(/[0-9]+)?$",
          "description": "BIP-32 style derivation path: m/purpose/coin_type/account/change/index (indices"
                         " are non-negative integers; supports Ethereum test vectors with coin type 60 and others)"
        },
        "uuid": {
          "type": "string",
          "format": "uuid",
          "description": "UUID v4 in canonical hyphenated format"
        },
        "version": {
          "const": 4
        }
      },
      "required": ["crypto", "path", "pubkey", "uuid", "version"],
      "title": "EIP-2335 Strict Keystore Schema (v4)"
    }
  }
}
