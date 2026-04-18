import asyncio
import requests
import datetime
from sqlalchemy.orm import Session
from config import settings
from agents.judge_agent import JudgeAgent, JudgmentResult

class WebhookDispatcher:
    def __init__(self, window_size: int = settings.WINDOW_SIZE):
        self.semaphore = asyncio.Semaphore(window_size)
        self.judge_agent = JudgeAgent()
        self.health_history = [] # track (timestamp, success boolean)

    def _sync_webhook(self, webhook_url: str, probe_text: str):
        try:
            res = requests.post(webhook_url, json={"prompt": probe_text}, timeout=15)
            # Normalize response payload if necessary
            data = res.json() if res.headers.get("Content-Type") == "application/json" else {"response": res.text}
            return res.status_code, data.get("response", res.text)
        except Exception as e:
            return 500, str(e)

    def get_health_failure_rate(self) -> float:
        # returns failure rate of last 20
        recent = self.health_history[-20:]
        if not recent: return 0.0
        failures = sum(1 for _, ok in recent if not ok)
        return failures / len(recent)

    async def dispatch_probe(self, probe_dict: dict, webhook_url: str, memory, db_callback=None):
        async with self.semaphore:
            probe_dict["status"] = "in_flight"
            probe_dict["dispatched_at"] = datetime.datetime.utcnow().isoformat()
            if db_callback:
                db_callback(probe_dict)

            # Send to webhook
            status_code, response_text = await asyncio.to_thread(self._sync_webhook, webhook_url, probe_dict["probe_text"])
            success = 200 <= status_code < 300
            
            self.health_history.append((datetime.datetime.utcnow(), success))
            probe_dict["response_received_at"] = datetime.datetime.utcnow().isoformat()
            probe_dict["victim_response"] = response_text
            
            if not success and ("timeout" in response_text.lower() or "connection" in response_text.lower()):
                probe_dict["status"] = "failed"
            else:
                # Judge the response
                judgment: JudgmentResult = await self.judge_agent.evaluate(probe_dict["probe_text"], response_text)
                
                probe_dict["status"] = "judged"
                probe_dict["severity"] = judgment.severity
                probe_dict["judgment"] = {
                    "vulnerability_found": judgment.vulnerability_found,
                    "weak_area": judgment.weak_area,
                    "key_insight": judgment.key_insight,
                    "strategy_tag": judgment.strategy_tag
                }
                
                # Update memory
                memory.update_judged(judgment)

            if db_callback:
                db_callback(probe_dict)
