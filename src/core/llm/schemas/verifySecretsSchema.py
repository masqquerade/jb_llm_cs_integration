from groq.types.chat.completion_create_params import ResponseFormatResponseFormatJsonSchema

verifySecretsSchema: ResponseFormatResponseFormatJsonSchema = {
    "type": "json_schema",
    "json_schema": {
        "name": "SecretTriageList",
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
                            "label": {"type": "string", "enum": ["secret", "likely_secret", "not_secret"]},
                            "reason": {"type": "string", "maxLength": 80}
                        },
                        "required": ["id", "label", "reason"]
                    },
                }
            },
            "required": ["items"]
        }
    }
}