import asyncio
import requests
import json
from config import settings

class OllamaClient:
    def __init__(self):
        self.base_url = settings.OLLAMA_URL
        self.timeout = settings.OLLAMA_TIMEOUT
        self.max_retries = 3

    def _sync_post(self, model: str, prompt: str, temperature: float):
        payload = {
            "model": model,
            "prompt": prompt,
            "temperature": temperature,
            "stream": False
        }
        res = requests.post(self.base_url, json=payload, timeout=self.timeout)
        res.raise_for_status()
        return res.json().get("response", "")

    async def generate_json(self, model: str, prompt: str, temperature: float = 0.7) -> dict | list:
        for attempt in range(self.max_retries):
            try:
                response_text = await asyncio.to_thread(self._sync_post, model, prompt, temperature)
                # Try to extract JSON block
                start_obj = response_text.find('{')
                end_obj = response_text.rfind('}') + 1
                start_arr = response_text.find('[')
                end_arr = response_text.rfind(']') + 1
                
                # Check which one came first and is valid
                if start_obj != -1 and (start_arr == -1 or start_obj < start_arr):
                    return json.loads(response_text[start_obj:end_obj])
                elif start_arr != -1:
                    return json.loads(response_text[start_arr:end_arr])
                    
            except Exception as e:
                print(f"OllamaClient JSON parse error attempt {attempt+1}: {e}")
                await asyncio.sleep(1)
        return {} # return empty dict on full failure

    async def generate_text(self, model: str, prompt: str, temperature: float = 0.7) -> str:
        for attempt in range(self.max_retries):
            try:
                return await asyncio.to_thread(self._sync_post, model, prompt, temperature)
            except Exception as e:
                print(f"OllamaClient Text generation error attempt {attempt+1}: {e}")
                await asyncio.sleep(1)
        return ""
