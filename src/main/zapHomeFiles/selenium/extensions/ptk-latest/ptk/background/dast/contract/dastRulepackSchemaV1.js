export const DAST_RULEPACK_SCHEMA_V1 = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "ptk-dast-extension-rulepack-v1.schema.json",
    "title": "PTK DAST Extension Canonical Rulepack v1",
    "description": "Extension-owned canonical envelope schema for PTK DAST rulepacks. The rule/action DSL remains intentionally open inside action, condition, target, and validation.rule/proof bodies.",
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
            "const": "ptk-dast-rulepack/v1"
        },
        "engine": {
            "const": "DAST"
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
            "pattern": "^[A-Za-z0-9_.-]+$"
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
        "capability": {
            "type": "string",
            "enum": [
                "boolean",
                "error",
                "union",
                "time",
                "oast",
                "xmlEncoding"
            ]
        },
        "findingSemantics": {
            "type": "string",
            "enum": [
                "unique",
                "repeatable"
            ]
        },
        "requestGrouping": {
            "type": "string",
            "enum": [
                "inherit",
                "bulk",
                "per_target"
            ]
        },
        "httpMethod": {
            "type": "string",
            "enum": [
                "GET",
                "POST",
                "PUT",
                "PATCH",
                "DELETE",
                "HEAD",
                "OPTIONS"
            ]
        },
        "engineCapabilityId": {
            "type": "string",
            "enum": [
                "smuggling_h1",
                "smuggling_h2",
                "websocket_handshake",
                "websocket_frames",
                "oast_callbacks",
                "race_burst",
                "multipart_files",
                "multi_identity"
            ],
            "description": "Stable engine prerequisite identifier."
        },
        "moduleRuntimeMode": {
            "type": "string",
            "enum": [
                "standard",
                "deserialization",
                "spa",
                "browser_nav",
                "browser_workflow"
            ]
        },
        "runtimeHook": {
            "type": "string",
            "enum": [
                "template_render_followup"
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
        "attackTaxonomyOverride": {
            "type": "object",
            "additionalProperties": false,
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
            },
            "default": {}
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
        "attackDocsOverride": {
            "type": "object",
            "additionalProperties": false,
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
            },
            "default": {}
        },
        "hardDenySelectorObject": {
            "type": "object",
            "additionalProperties": false,
            "minProperties": 1,
            "properties": {
                "regex": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "names": {
                    "$ref": "#/$defs/stringSet",
                    "minItems": 1
                }
            }
        },
        "hardDenySelector": {
            "oneOf": [
                {
                    "const": true
                },
                {
                    "$ref": "#/$defs/nonEmptyString"
                },
                {
                    "$ref": "#/$defs/stringSet",
                    "minItems": 1
                },
                {
                    "$ref": "#/$defs/hardDenySelectorObject"
                }
            ]
        },
        "moduleExecution": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "findingSemantics",
                "capabilities",
                "requiredEngineCapabilities",
                "allowStrategyBulk",
                "allowAuthLikeTargets",
                "allowHardDeniedTargets"
            ],
            "properties": {
                "findingSemantics": {
                    "$ref": "#/$defs/findingSemantics",
                    "default": "repeatable"
                },
                "capabilities": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/capability"
                    },
                    "uniqueItems": true,
                    "default": []
                },
                "requiredEngineCapabilities": {
                    "type": "array",
                    "description": "Engine/runtime prerequisites that must be available before this module can run. The extension should skip the module when any required capability is unsupported.",
                    "items": {
                        "$ref": "#/$defs/engineCapabilityId"
                    },
                    "uniqueItems": true,
                    "default": []
                },
                "allowStrategyBulk": {
                    "type": "boolean",
                    "description": "If true, the module may inherit scan-strategy bulk request grouping. If false, strategy defaults must not force bulk for this module.",
                    "default": true
                },
                "allowAuthLikeTargets": {
                    "type": "boolean",
                    "default": false
                },
                "allowHardDeniedTargets": {
                    "type": "object",
                    "additionalProperties": false,
                    "default": {},
                    "properties": {
                        "params": {
                            "$ref": "#/$defs/hardDenySelector"
                        },
                        "cookies": {
                            "$ref": "#/$defs/hardDenySelector"
                        },
                        "headers": {
                            "$ref": "#/$defs/hardDenySelector"
                        }
                    }
                },
                "prefilters": {
                    "type": "object",
                    "additionalProperties": false,
                    "default": {},
                    "properties": {
                        "methods": {
                            "type": "array",
                            "items": {
                                "$ref": "#/$defs/httpMethod"
                            },
                            "uniqueItems": true,
                            "default": []
                        },
                        "requiresBody": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresJsonBody": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresXmlBody": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresQueryParams": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresQueryOrBodyParams": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresCookies": {
                            "type": "boolean",
                            "default": false
                        },
                        "requiresHeaders": {
                            "type": "boolean",
                            "default": false
                        }
                    }
                }
            }
        },
        "deserializationMutationKind": {
            "type": "string",
            "enum": [
                "semantic",
                "control",
                "parser_probe"
            ]
        },
        "deserializationFamily": {
            "type": "string",
            "enum": [
                "php_serialized",
                "java_serialized",
                "dotnet_viewstate",
                "ruby_marshaled",
                "json_type_metadata"
            ]
        },
        "deserializationRuntimeConfig": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "mutationKind": {
                    "$ref": "#/$defs/deserializationMutationKind",
                    "default": "semantic"
                },
                "familyAllow": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/deserializationFamily"
                    },
                    "uniqueItems": true
                },
                "minCandidateConfidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 1
                },
                "maxCandidates": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10
                }
            }
        },
        "trackingConfirmation": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "default": false
                },
                "mode": {
                    "type": "string",
                    "enum": [
                        "followup_get"
                    ],
                    "default": "followup_get"
                },
                "marker": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "filename": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "confidence": {
                    "type": "number",
                    "minimum": 0,
                    "maximum": 100
                },
                "signals": {
                    "type": "array",
                    "items": {
                        "type": "string",
                        "enum": [
                            "response_url",
                            "location_header",
                            "body_regex"
                        ]
                    },
                    "uniqueItems": true
                }
            }
        },
        "oastConfirmation": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "enabled": {
                    "type": "boolean",
                    "default": false
                },
                "domain": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "domains": {
                    "$ref": "#/$defs/stringSet",
                    "minItems": 1
                },
                "requireConfirmation": {
                    "type": "boolean",
                    "default": false
                }
            },
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "enabled": {
                                "const": true
                            }
                        },
                        "required": [
                            "enabled"
                        ]
                    },
                    "then": {
                        "anyOf": [
                            {
                                "required": [
                                    "domain"
                                ]
                            },
                            {
                                "required": [
                                    "domains"
                                ]
                            }
                        ]
                    }
                }
            ]
        },
        "spaRuntimeConfig": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "checks": {
                    "$ref": "#/$defs/stringSet"
                },
                "payloads": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/nonEmptyString"
                    }
                },
                "markerToken": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "markerDomain": {
                    "$ref": "#/$defs/nonEmptyString"
                }
            }
        },
        "browserNavRuntimeConfig": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "checks": {
                    "$ref": "#/$defs/stringSet"
                },
                "markerToken": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "settleMs": {
                    "type": "integer",
                    "minimum": 0
                }
            }
        },
        "browserWorkflowRuntimeConfig": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "flow": {
                    "enum": [
                        "auth_2fa_bypass"
                    ]
                },
                "protectedPaths": {
                    "$ref": "#/$defs/stringSet"
                },
                "challengeRegex": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "loggedOutRegex": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "loggedInRegex": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "settleMs": {
                    "type": "integer",
                    "minimum": 0
                }
            }
        },
        "runtimeConfirmation": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "oast": {
                    "$ref": "#/$defs/oastConfirmation"
                },
                "tracking": {
                    "$ref": "#/$defs/trackingConfirmation"
                }
            }
        },
        "runtimeConfig": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "deserialization": {
                    "$ref": "#/$defs/deserializationRuntimeConfig"
                },
                "spa": {
                    "$ref": "#/$defs/spaRuntimeConfig"
                },
                "browserNav": {
                    "$ref": "#/$defs/browserNavRuntimeConfig"
                },
                "browserWorkflow": {
                    "$ref": "#/$defs/browserWorkflowRuntimeConfig"
                }
            }
        },
        "moduleRuntime": {
            "type": "object",
            "additionalProperties": false,
            "description": "Module-level runtime defaults for execution mode, additive hooks, confirmation channels, and mode-specific config.",
            "required": [
                "mode",
                "hooks",
                "confirmation",
                "config"
            ],
            "properties": {
                "mode": {
                    "$ref": "#/$defs/moduleRuntimeMode",
                    "default": "standard"
                },
                "hooks": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/runtimeHook"
                    },
                    "uniqueItems": true,
                    "default": []
                },
                "confirmation": {
                    "$ref": "#/$defs/runtimeConfirmation"
                },
                "config": {
                    "$ref": "#/$defs/runtimeConfig"
                }
            },
            "allOf": [
                {
                    "if": {
                        "properties": {
                            "mode": {
                                "const": "deserialization"
                            }
                        },
                        "required": [
                            "mode"
                        ]
                    },
                    "then": {
                        "properties": {
                            "config": {
                                "required": [
                                    "deserialization"
                                ]
                            }
                        }
                    }
                },
                {
                    "if": {
                        "properties": {
                            "mode": {
                                "const": "spa"
                            }
                        },
                        "required": [
                            "mode"
                        ]
                    },
                    "then": {
                        "properties": {
                            "config": {
                                "required": [
                                    "spa"
                                ]
                            }
                        }
                    }
                },
                {
                    "if": {
                        "properties": {
                            "mode": {
                                "const": "browser_nav"
                            }
                        },
                        "required": [
                            "mode"
                        ]
                    },
                    "then": {
                        "properties": {
                            "config": {
                                "required": [
                                    "browserNav"
                                ]
                            }
                        }
                    }
                },
                {
                    "if": {
                        "properties": {
                            "mode": {
                                "const": "browser_workflow"
                            }
                        },
                        "required": [
                            "mode"
                        ]
                    },
                    "then": {
                        "properties": {
                            "config": {
                                "required": [
                                    "browserWorkflow"
                                ]
                            }
                        }
                    }
                }
            ]
        },
        "attackRuntime": {
            "type": "object",
            "additionalProperties": false,
            "description": "Attack-level runtime overrides. hooks are additive. confirmation and config override per-subsection when provided. execution mode is owned by module.runtime.mode.",
            "required": [
                "hooks",
                "confirmation",
                "config"
            ],
            "properties": {
                "hooks": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/runtimeHook"
                    },
                    "uniqueItems": true,
                    "default": []
                },
                "confirmation": {
                    "$ref": "#/$defs/runtimeConfirmation"
                },
                "config": {
                    "$ref": "#/$defs/runtimeConfig"
                }
            }
        },
        "validation": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "rule"
            ],
            "properties": {
                "rule": {
                    "oneOf": [
                        {
                            "type": "boolean"
                        },
                        {
                            "type": "object"
                        }
                    ]
                },
                "proof": {
                    "type": "object"
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
        "attackMetadata": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "taxonomy",
                "docs",
                "constants",
                "extensions"
            ],
            "properties": {
                "taxonomy": {
                    "$ref": "#/$defs/attackTaxonomyOverride"
                },
                "docs": {
                    "$ref": "#/$defs/attackDocsOverride"
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
        "module": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "id",
                "name",
                "type",
                "async",
                "runtime",
                "metadata",
                "attacks"
            ],
            "properties": {
                "id": {
                    "$ref": "#/$defs/idString"
                },
                "name": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "type": {
                    "type": "string",
                    "enum": [
                        "active",
                        "passive"
                    ]
                },
                "async": {
                    "type": "boolean"
                },
                "runtime": {
                    "$ref": "#/$defs/moduleRuntime"
                },
                "metadata": {
                    "$ref": "#/$defs/moduleMetadata"
                },
                "attacks": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/attack"
                    }
                }
            }
        },
        "attack": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "id",
                "name",
                "runtime",
                "action",
                "validation",
                "condition",
                "target",
                "requestGrouping",
                "metadata"
            ],
            "properties": {
                "id": {
                    "$ref": "#/$defs/idString"
                },
                "name": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "runtime": {
                    "$ref": "#/$defs/attackRuntime"
                },
                "action": {
                    "type": "object",
                    "default": {}
                },
                "validation": {
                    "$ref": "#/$defs/validation"
                },
                "condition": {
                    "oneOf": [
                        {
                            "type": "boolean"
                        },
                        {
                            "type": "object"
                        }
                    ],
                    "default": {}
                },
                "target": {
                    "type": "object",
                    "default": {}
                },
                "requestGrouping": {
                    "$ref": "#/$defs/requestGrouping",
                    "description": "Attack-level request grouping. inherit follows scan strategy unless the module blocks strategy bulk; bulk forces one coordinated request; per_target forces isolated target expansion.",
                    "default": "inherit"
                },
                "metadata": {
                    "$ref": "#/$defs/attackMetadata"
                }
            }
        }
    }
}

export default DAST_RULEPACK_SCHEMA_V1
