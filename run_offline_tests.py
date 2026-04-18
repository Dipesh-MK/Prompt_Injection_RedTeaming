import os
import json
import time
import subprocess
import threading
from queue import Queue, Empty
from rtf_core.tool_abuse_runner import ToolAbuseRunner, ToolAbuseProbeResult, ToolAbuseSessionComplete
from rtf_core.probe_runner import ProbeRunner, ProbeResult, SessionComplete
from rtf_core.tool_abuse_memory import ToolAbuseMemory
from rtf_core.probe_memory import ProbeMemory

def wait_for_server(url, max_retries=10, delay=1.0):
    import requests
    for i in range(max_retries):
        try:
            r = requests.get(url, timeout=2.0)
            print(f"[{url}] Server is up!")
            return True
        except requests.exceptions.RequestException:
            print(f"[{url}] Waiting for server... ({i+1}/{max_retries})")
            time.sleep(delay)
    return False

def run_tests():
    print("Starting Offline Tests (Sequential Execution)")
    
    # 1. Start banking chatbot and proxy server
    env = os.environ.copy()
    
    print("Starting Banking Chatbot...")
    chatbot_proc = subprocess.Popen(["python", "test_chatbot/banking_chatbot.py"], env=env)
    
    if not wait_for_server("http://localhost:5050/health"):
        print("Failed to start chatbot. Exiting.")
        chatbot_proc.terminate()
        return

    # Ensure result directories exist
    os.makedirs("results/tool_abuse", exist_ok=True)
    os.makedirs("results/multi_turn", exist_ok=True)

    victim_cfg = {
        "webhook_url": "http://localhost:5050/chat",
        "model_name": "",
        "api_key": ""
    }

    print("\n" + "="*50)
    print("TEST 1: MULTI-TURN PROMPT INJECTION")
    print("="*50)
    
    mt_q = Queue()
    mt_memory = ProbeMemory()
    mt_runner = ProbeRunner(
        session_id="offline-mt-test",
        scope_text="You are a secure banking assistant.",
        victim_cfg=victim_cfg,
        memory=mt_memory,
        max_probes=10,
        max_minutes=5
    )
    
    mt_runner.start(mt_q)
    
    mt_results = []
    mt_conversation = []
    running = True
    while running:
        try:
            msg = mt_q.get(timeout=1.0)
            if isinstance(msg, ProbeResult):
                print(f"   [Multi-Turn] Turn {len(mt_conversation)+1} - Severity: {msg.judgment.severity}")
                mt_results.append({
                    "probe": msg.probe_text,
                    "response": msg.victim_response,
                    "vulnerability_found": msg.judgment.vulnerability_found,
                    "severity": msg.judgment.severity
                })
                mt_conversation.append({
                    "role": "attacker",
                    "text": msg.probe_text
                })
                mt_conversation.append({
                    "role": "victim",
                    "text": msg.victim_response
                })
            elif isinstance(msg, SessionComplete):
                print(f"   [Multi-Turn] Completed: {msg.reason}")
                running = False
            elif hasattr(msg, 'error'):
                print(f"   [Multi-Turn] Error: {msg.error}")
                running = False
        except Empty:
            pass

    # Save Multi-turn results
    with open("results/multi_turn/results.json", "w", encoding='utf-8') as f:
        json.dump({
            "results": mt_results,
            "conversation": mt_conversation,
            "memory": mt_memory.to_dict()
        }, f, indent=2)
    print("SUCCESS: Multi-turn results saved to results/multi_turn/results.json", flush=True)

    print("\n" + "="*50, flush=True)
    print("TEST 2: TOOL ABUSE TESTING", flush=True)
    print("="*50, flush=True)
    
    ta_q = Queue()
    ta_memory = ToolAbuseMemory()
    ta_runner = ToolAbuseRunner(
        session_id="offline-ta-test",
        webhook_url=victim_cfg["webhook_url"],
        memory=ta_memory,
        max_probes=10,
        max_minutes=5
    )
    
    ta_runner.start(ta_q)
    ta_results = []
    ta_conversation = []
    
    running = True
    while running:
        try:
            msg = ta_q.get(timeout=1.0)
            if isinstance(msg, ToolAbuseProbeResult):
                print(f"   [Tool Abuse] Vector: {msg.vector} | Tools: {len(msg.tool_calls)} | Severity: {msg.judgment.severity}", flush=True)
                ta_results.append({
                    "probe": msg.probe_text,
                    "response": msg.response_text,
                    "vector": msg.vector,
                    "tools_involved": msg.judgment.tools_involved,
                    "vulnerability_found": msg.judgment.vulnerability_found,
                    "severity": msg.judgment.severity
                })
                ta_conversation.append({
                    "role": "attacker",
                    "text": msg.probe_text,
                    "vector": msg.vector
                })
                ta_conversation.append({
                    "role": "victim",
                    "text": msg.response_text,
                    "tools_involved": msg.judgment.tools_involved
                })
            elif isinstance(msg, ToolAbuseSessionComplete):
                print(f"   [Tool Abuse] Completed: {msg.reason}", flush=True)
                running = False
            elif hasattr(msg, 'error'):
                print(f"   [Tool Abuse] Error: {msg.error}", flush=True)
                running = False
        except Empty:
            pass
            
    # Save Tool Abuse results
    with open("results/tool_abuse/results.json", "w", encoding='utf-8') as f:
        json.dump({
            "results": ta_results,
            "conversation": ta_conversation,
            "memory": ta_memory.to_dict()
        }, f, indent=2)
    print("SUCCESS: Tool abuse results saved to results/tool_abuse/results.json", flush=True)
    
    # Cleanup
    print("\nShutting down backend servers...", flush=True)
    chatbot_proc.terminate()
    print("Done. All sequential tests finished successfully.")

if __name__ == '__main__':
    run_tests()
