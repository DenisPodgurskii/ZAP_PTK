export const SAST_RULEPACK_SCHEMA_V1 = {
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "$id": "ptk-sast-extension-rulepack-v1.schema.json",
  "title": "PTK SAST Extension Canonical Rulepack v1",
  "description": "Extension-owned canonical envelope schema for PTK SAST rulepacks. The matcher DSL remains intentionally open inside pattern.detector.matches[] and taint.detector overlay bodies. Discovery artifacts are intentionally out of scope for this schema and remain runtime-owned.",
  "type": "object",
  "additionalProperties": false,
  "required": [
    "schema",
    "engine",
    "version",
    "modules"
  ],
  "properties": {
    "schema": {
      "const": "ptk-sast-rulepack/v1"
    },
    "engine": {
      "const": "SAST"
    },
    "version": {
      "const": 1
    },
    "modules": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/module"
      }
    }
  },
  "$defs": {
    "idString": {
      "type": "string",
      "minLength": 1,
      "pattern": "^[a-z0-9_:-]+$"
    },
    "nonEmptyString": {
      "type": "string",
      "minLength": 1
    },
    "stringSet": {
      "type": "array",
      "items": {
        "$ref": "#/$defs/nonEmptyString"
      },
      "uniqueItems": true
    },
    "severity": {
      "type": "string",
      "enum": [
        "critical",
        "high",
        "medium",
        "low",
        "info"
      ]
    },
    "findingKind": {
      "type": "string",
      "enum": [
        "finding",
        "hint"
      ]
    },
    "ruleMode": {
      "type": "string",
      "enum": [
        "pattern",
        "taint"
      ]
    },
    "moduleType": {
      "type": "string",
      "enum": [
        "static"
      ]
    },
    "links": {
      "type": "object",
      "default": {},
      "additionalProperties": {
        "type": "string",
        "minLength": 1
      }
    },
    "moduleTaxonomy": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "severity",
        "category",
        "vulnId",
        "owasp",
        "cwe",
        "tags"
      ],
      "properties": {
        "severity": {
          "$ref": "#/$defs/severity"
        },
        "category": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "vulnId": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "owasp": {
          "$ref": "#/$defs/stringSet",
          "default": []
        },
        "cwe": {
          "$ref": "#/$defs/stringSet",
          "default": []
        },
        "tags": {
          "$ref": "#/$defs/stringSet",
          "default": []
        }
      }
    },
    "ruleTaxonomyOverride": {
      "type": "object",
      "additionalProperties": false,
      "default": {},
      "properties": {
        "severity": {
          "$ref": "#/$defs/severity"
        },
        "category": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "vulnId": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "owasp": {
          "$ref": "#/$defs/stringSet"
        },
        "cwe": {
          "$ref": "#/$defs/stringSet"
        },
        "tags": {
          "$ref": "#/$defs/stringSet"
        }
      }
    },
    "moduleDocs": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "description",
        "recommendation",
        "links"
      ],
      "properties": {
        "description": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "recommendation": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "links": {
          "$ref": "#/$defs/links"
        }
      }
    },
    "ruleDocsOverride": {
      "type": "object",
      "additionalProperties": false,
      "default": {},
      "properties": {
        "description": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "recommendation": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "links": {
          "$ref": "#/$defs/links"
        }
      }
    },
    "moduleExecution": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "findingKind",
        "maxFindings",
        "confidenceDefault"
      ],
      "properties": {
        "findingKind": {
          "$ref": "#/$defs/findingKind",
          "default": "finding"
        },
        "maxFindings": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1,
          "default": null
        },
        "confidenceDefault": {
          "type": [
            "number",
            "null"
          ],
          "minimum": 0,
          "maximum": 100,
          "default": null
        }
      }
    },
    "ruleExecution": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "findingKind",
        "maxFindings",
        "originLimit",
        "depthLimit",
        "confidenceDefault"
      ],
      "properties": {
        "findingKind": {
          "$ref": "#/$defs/findingKind"
        },
        "maxFindings": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1,
          "default": null
        },
        "originLimit": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1,
          "default": null
        },
        "depthLimit": {
          "type": [
            "integer",
            "null"
          ],
          "minimum": 1,
          "default": null
        },
        "confidenceDefault": {
          "type": [
            "number",
            "null"
          ],
          "minimum": 0,
          "maximum": 100,
          "default": null
        }
      }
    },
    "moduleMetadata": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "taxonomy",
        "docs",
        "execution",
        "constants",
        "extensions"
      ],
      "properties": {
        "taxonomy": {
          "$ref": "#/$defs/moduleTaxonomy"
        },
        "docs": {
          "$ref": "#/$defs/moduleDocs"
        },
        "execution": {
          "$ref": "#/$defs/moduleExecution"
        },
        "constants": {
          "type": "object",
          "default": {}
        },
        "extensions": {
          "type": "object",
          "default": {}
        }
      }
    },
    "ruleMetadata": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "taxonomy",
        "docs",
        "execution",
        "constants",
        "extensions"
      ],
      "properties": {
        "taxonomy": {
          "$ref": "#/$defs/ruleTaxonomyOverride"
        },
        "docs": {
          "$ref": "#/$defs/ruleDocsOverride"
        },
        "execution": {
          "$ref": "#/$defs/ruleExecution"
        },
        "constants": {
          "type": "object",
          "default": {}
        },
        "extensions": {
          "type": "object",
          "default": {}
        }
      }
    },
    "catalogRef": {
      "oneOf": [
        {
          "$ref": "#/$defs/nonEmptyString"
        },
        {
          "type": "object",
          "additionalProperties": false,
          "required": [
            "id"
          ],
          "properties": {
            "id": {
              "$ref": "#/$defs/nonEmptyString"
            },
            "overlay": {
              "type": "object",
              "default": {}
            }
          }
        }
      ]
    },
    "patternDetector": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "matches"
      ],
      "properties": {
        "matches": {
          "type": "array",
          "minItems": 1,
          "items": {
            "type": "object"
          }
        }
      }
    },
    "taintDetector": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "sources",
        "sinks",
        "sanitizers",
        "propagators",
        "taintKinds"
      ],
      "properties": {
        "sources": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/catalogRef"
          },
          "uniqueItems": true,
          "default": []
        },
        "sinks": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/catalogRef"
          },
          "uniqueItems": true,
          "default": []
        },
        "sanitizers": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/catalogRef"
          },
          "uniqueItems": true,
          "default": []
        },
        "propagators": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/catalogRef"
          },
          "uniqueItems": true,
          "default": []
        },
        "taintKinds": {
          "$ref": "#/$defs/stringSet",
          "default": []
        }
      }
    },
    "module": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "name",
        "type",
        "async",
        "metadata",
        "rules"
      ],
      "properties": {
        "id": {
          "$ref": "#/$defs/idString"
        },
        "name": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "type": {
          "$ref": "#/$defs/moduleType"
        },
        "async": {
          "type": "boolean"
        },
        "metadata": {
          "$ref": "#/$defs/moduleMetadata"
        },
        "rules": {
          "type": "array",
          "items": {
            "$ref": "#/$defs/rule"
          }
        }
      }
    },
    "rule": {
      "type": "object",
      "additionalProperties": false,
      "required": [
        "id",
        "name",
        "mode",
        "metadata",
        "detector"
      ],
      "properties": {
        "id": {
          "$ref": "#/$defs/idString"
        },
        "name": {
          "$ref": "#/$defs/nonEmptyString"
        },
        "mode": {
          "$ref": "#/$defs/ruleMode"
        },
        "metadata": {
          "$ref": "#/$defs/ruleMetadata"
        },
        "detector": {
          "type": "object"
        }
      },
      "allOf": [
        {
          "if": {
            "properties": {
              "mode": {
                "const": "pattern"
              }
            },
            "required": [
              "mode"
            ]
          },
          "then": {
            "properties": {
              "detector": {
                "$ref": "#/$defs/patternDetector"
              },
              "metadata": {
                "properties": {
                  "execution": {
                    "properties": {
                      "originLimit": {
                        "const": null
                      },
                      "depthLimit": {
                        "const": null
                      }
                    }
                  }
                }
              }
            }
          }
        },
        {
          "if": {
            "properties": {
              "mode": {
                "const": "taint"
              }
            },
            "required": [
              "mode"
            ]
          },
          "then": {
            "properties": {
              "detector": {
                "$ref": "#/$defs/taintDetector"
              }
            }
          }
        }
      ]
    }
  }
}

export default SAST_RULEPACK_SCHEMA_V1
