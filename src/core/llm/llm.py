from groq import Groq

from src.core.llm.prompts_manager import getVerifyPrompt

class LLM:
    def __init__(self, api_key: str, model: str):
        self.client = Groq(api_key=api_key)
        self.model = model

    def verifyBatch(self, batch, schema, prompt_filename):
        if isinstance(batch, dict):
            items = [batch]
        else:
            items = batch

        completion = self.client.chat.completions.create(
            model=self.model,
            messages=[
                {
                    "role": "user",
                    "content": getVerifyPrompt(items, prompt_filename)
                }
            ],
            response_format=schema,
            temperature=0,
            top_p=1,
            max_tokens=512,
        )

        return completion.choices[0].message.content