from groq.types.chat.completion_create_params import ResponseFormatResponseFormatJsonSchema

verifySensitiveSchema: ResponseFormatResponseFormatJsonSchema = {
    "type": "json_schema",
    "json_schema": {
        "name": "SensitiveDataTriageList",
        "schema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": False,
                        "properties": {
                            "id": {"type": "integer"},
                            "label": {
                                "type": "string",
                                "enum": ["sensitive", "likely_sensitive", "not_sensitive"]
                            },
                            "reason": {"type": "string", "maxLength": 80}
                        },
                        "required": ["id", "label", "reason"]
                    }
                }
            },
            "required": ["items"]
        }
    }
}

