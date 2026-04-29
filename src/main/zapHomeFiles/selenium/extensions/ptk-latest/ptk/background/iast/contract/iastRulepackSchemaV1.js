export const IAST_RULEPACK_SCHEMA_V1 = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "$id": "ptk-iast-extension-rulepack-v1.schema.json",
    "title": "PTK IAST Extension Canonical Rulepack v1",
    "description": "Extension-owned canonical envelope schema for PTK IAST rulepacks. Runtime instrumentation, taint propagation, trust, reporting, and analysis semantics remain extension-owned. Rulepacks may only compose known catalog capabilities.",
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
            "const": "ptk-iast-rulepack/v1"
        },
        "engine": {
            "const": "IAST"
        },
        "version": {
            "const": 1
        },
        "policy": {
            "$ref": "#/$defs/policyRef"
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
        "catalogCode": {
            "type": "string",
            "minLength": 1,
            "pattern": "^[A-Za-z0-9._-]+$"
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
        "moduleType": {
            "type": "string",
            "enum": [
                "runtime"
            ]
        },
        "findingAggregationMode": {
            "type": "string",
            "enum": [
                "route-source-sink",
                "route-source-sink-callsite",
                "source-sink",
                "source-sink-callsite"
            ]
        },
        "presentation": {
            "type": "object",
            "additionalProperties": false,
            "default": {},
            "properties": {
                "aggregate": {
                    "$ref": "#/$defs/findingAggregationMode"
                }
            }
        },
        "policyRef": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "id": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "name": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "description": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "updated_at": {
                    "$ref": "#/$defs/nonEmptyString"
                }
            }
        },
        "links": {
            "type": "object",
            "default": {},
            "additionalProperties": {
                "type": "string",
                "minLength": 1
            }
        },
        "moduleMetadata": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "description",
                "recommendation",
                "severity",
                "category",
                "vulnId"
            ],
            "properties": {
                "description": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "recommendation": {
                    "$ref": "#/$defs/nonEmptyString"
                },
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
                },
                "links": {
                    "$ref": "#/$defs/links"
                },
                "presentation": {
                    "$ref": "#/$defs/presentation"
                }
            }
        },
        "ruleMetadata": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "description": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "recommendation": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "severity": {
                    "$ref": "#/$defs/severity"
                },
                "category": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "vulnId": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "confidence": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100
                },
                "owasp": {
                    "$ref": "#/$defs/stringSet"
                },
                "cwe": {
                    "$ref": "#/$defs/stringSet"
                },
                "tags": {
                    "$ref": "#/$defs/stringSet"
                },
                "links": {
                    "$ref": "#/$defs/links"
                },
                "presentation": {
                    "$ref": "#/$defs/presentation"
                }
            },
            "default": {}
        },
        "hookField": {
            "type": "string",
            "minLength": 1,
            "pattern": "^[A-Za-z0-9._-]+$"
        },
        "objectType": {
            "allOf": [
                {
                    "$ref": "#/$defs/hookField"
                },
                {
                    "not": {
                        "enum": [
                            "Object",
                            "Function",
                            "Array",
                            "Promise"
                        ]
                    }
                }
            ]
        },
        "propertySetterHook": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "kind",
                "property"
            ],
            "properties": {
                "kind": {
                    "const": "propertySetter"
                },
                "objectType": {
                    "$ref": "#/$defs/objectType"
                },
                "objectPath": {
                    "$ref": "#/$defs/hookField"
                },
                "property": {
                    "$ref": "#/$defs/hookField"
                }
            },
            "oneOf": [
                {
                    "required": [
                        "objectType"
                    ]
                },
                {
                    "required": [
                        "objectPath"
                    ]
                }
            ]
        },
        "methodCallHook": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "kind",
                "method"
            ],
            "properties": {
                "kind": {
                    "const": "methodCall"
                },
                "objectType": {
                    "$ref": "#/$defs/objectType"
                },
                "objectPath": {
                    "$ref": "#/$defs/hookField"
                },
                "method": {
                    "$ref": "#/$defs/hookField"
                },
                "argIndex": {
                    "type": "integer",
                    "minimum": 0
                }
            },
            "oneOf": [
                {
                    "required": [
                        "objectType"
                    ]
                },
                {
                    "required": [
                        "objectPath"
                    ]
                }
            ]
        },
        "constructorHook": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "kind",
                "objectPath"
            ],
            "properties": {
                "kind": {
                    "const": "constructor"
                },
                "objectPath": {
                    "$ref": "#/$defs/hookField"
                }
            }
        },
        "attributeHook": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "kind",
                "objectType"
            ],
            "properties": {
                "kind": {
                    "const": "attribute"
                },
                "objectType": {
                    "$ref": "#/$defs/objectType"
                },
                "attribute": {
                    "$ref": "#/$defs/hookField"
                },
                "attributePrefix": {
                    "$ref": "#/$defs/hookField"
                }
            },
            "oneOf": [
                {
                    "required": [
                        "attribute"
                    ]
                },
                {
                    "required": [
                        "attributePrefix"
                    ]
                }
            ]
        },
        "eventHook": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "kind",
                "objectPath",
                "event"
            ],
            "properties": {
                "kind": {
                    "const": "event"
                },
                "objectPath": {
                    "$ref": "#/$defs/hookField"
                },
                "event": {
                    "$ref": "#/$defs/hookField"
                }
            }
        },
        "hook": {
            "oneOf": [
                {
                    "$ref": "#/$defs/propertySetterHook"
                },
                {
                    "$ref": "#/$defs/methodCallHook"
                },
                {
                    "$ref": "#/$defs/constructorHook"
                },
                {
                    "$ref": "#/$defs/attributeHook"
                },
                {
                    "$ref": "#/$defs/eventHook"
                }
            ]
        },
        "sanitizerAction": {
            "type": "string",
            "enum": [
                "suppress",
                "lower_confidence"
            ]
        },
        "conditions": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "requiresTaint": {
                    "type": "boolean"
                },
                "requiresCrossOrigin": {
                    "type": "boolean"
                }
            },
            "default": {}
        },
        "limits": {
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "maxTriggersPerSession": {
                    "type": "integer",
                    "minimum": 1
                },
                "maxReports": {
                    "type": "integer",
                    "minimum": 1
                }
            },
            "default": {}
        },
        "rule": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "id",
                "name",
                "sinkId"
            ],
            "properties": {
                "schemaVersion": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "id": {
                    "$ref": "#/$defs/idString"
                },
                "name": {
                    "$ref": "#/$defs/nonEmptyString"
                },
                "sinkId": {
                    "$ref": "#/$defs/catalogCode"
                },
                "severity": {
                    "$ref": "#/$defs/severity"
                },
                "sources": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/catalogCode"
                    },
                    "uniqueItems": true
                },
                "sanitizersAllowed": {
                    "type": "array",
                    "items": {
                        "$ref": "#/$defs/catalogCode"
                    },
                    "uniqueItems": true
                },
                "onSanitized": {
                    "$ref": "#/$defs/sanitizerAction"
                },
                "hook": {
                    "$ref": "#/$defs/hook"
                },
                "conditions": {
                    "$ref": "#/$defs/conditions"
                },
                "limits": {
                    "$ref": "#/$defs/limits"
                },
                "metadata": {
                    "$ref": "#/$defs/ruleMetadata"
                }
            }
        },
        "module": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "id",
                "type",
                "async",
                "name",
                "metadata",
                "rules"
            ],
            "properties": {
                "id": {
                    "$ref": "#/$defs/idString"
                },
                "type": {
                    "$ref": "#/$defs/moduleType"
                },
                "async": {
                    "type": "boolean"
                },
                "name": {
                    "$ref": "#/$defs/nonEmptyString"
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
        }
    }
}
