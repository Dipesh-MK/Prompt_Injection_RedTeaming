"""
rtf_core/probe_runner.py
------------------------
Orchestrates a single probe cycle:
  1. Attacker generates probes
  2. Each probe is sent to the victim webhook
  3. Judge evaluates the response
  4. Memory is updated
  5. DB is written

Designed to be called from a background thread in Streamlit.
Uses a queue to push results to the UI in real-time.
"""

import uuid
import datetime
import threading
from typing import Callable, Optional
from queue import Queue

from rtf_core import settings, attacker, judge
from rtf_core.probe_memory import ProbeMemory
from rtf_core.victim_client import VictimClient
from rtf_core.db import ProbeDB, SessionDB, get_session


# ── Message types posted to the UI queue ──────────────────────────────────────

class ProbeResult:
    """Posted to the queue after each probe is judged."""
    def __init__(self, probe_text, victim_response, judgment, probe_id):
        self.probe_text      = probe_text
        self.victim_response = victim_response
        self.judgment        = judgment        # rtf_core.judge.Judgment
        self.probe_id        = probe_id

class SessionComplete:
    """Posted when the session ends (naturally or manually)."""
    def __init__(self, reason: str):
        self.reason = reason

class SessionError:
    """Posted on unrecoverable error."""
    def __init__(self, error: str):
        self.error = error


# ── Runner ────────────────────────────────────────────────────────────────────

class ProbeRunner:
    """
    Drives a complete probe session.
    Call `start(queue)` to launch in a background thread.
    Call `stop()` from the UI thread to signal graceful termination.
    """

    def __init__(
        self,
        session_id:     str,
        scope_text:     str,
        victim_cfg:     dict,           # keys: webhook_url, model_name, api_key, timeout
        memory:         ProbeMemory,
        max_probes:     int = None,
        max_minutes:    int = None,
        attacker_model: str = None,     # overrides settings.ATTACKER_MODEL
        judge_model:    str = None,     # overrides settings.JUDGE_MODEL
    ):
        self.session_id     = session_id
        self.scope_text     = scope_text
        self.victim_cfg     = victim_cfg
        self.memory         = memory
        self.max_probes     = max_probes  or settings.MAX_PROBES_PER_SESSION
        self.max_minutes    = max_minutes or settings.MAX_SESSION_MINUTES
        self.attacker_model = attacker_model or settings.ATTACKER_MODEL
        self.judge_model    = judge_model    or settings.JUDGE_MODEL

        self._stop_event  = threading.Event()
        self._victim      = VictimClient(
            webhook_url = victim_cfg["webhook_url"],
            model_name  = victim_cfg.get("model_name"),
            api_key     = victim_cfg.get("api_key"),
            timeout     = int(victim_cfg.get("timeout", 30)),
        )

    def stop(self):
        """Signal the runner to stop after the current probe."""
        self._stop_event.set()

    def start(self, queue: Queue):
        """
        Entry point for the background thread.
        Posts ProbeResult / SessionComplete / SessionError to `queue`.
        """
        thread = threading.Thread(
            target=self._run_loop,
            args=(queue,),
            daemon=True,
        )
        thread.start()
        return thread

    def _run_loop(self, queue: Queue):
        deadline = datetime.datetime.utcnow() + datetime.timedelta(minutes=self.max_minutes)

        try:
            # Initialise session row in DB
            with get_session() as db:
                sess_row = SessionDB(
                    session_id  = self.session_id,
                    scope_text  = self.scope_text,
                    webhook_url = self.victim_cfg["webhook_url"],
                    model_name  = self.victim_cfg.get("model_name", ""),
                    status      = "active",
                )
                db.merge(sess_row)

            while not self._stop_event.is_set():
                # --- Step 0: Intelligent Stopping ---
                # Every 2 batches (approx 6 probes), run the Analyst
                if self.memory.probe_count > 0 and self.memory.probe_count % 6 == 0:
                    analysis = judge.analyze_session_state(
                        memory_snapshot = self.memory.to_dict(),
                        model           = self.judge_model
                    )
                    if analysis.should_stop:
                        queue.put(SessionComplete(f"AI Analyst Stop: {analysis.stop_reason}"))
                        break
                    else:
                        # Analyst might suggest a pivot, currently logged for debugging
                        print(f"[ProbeRunner] Analyst Style Summary: {analysis.style_summary}")
                        print(f"[ProbeRunner] Next Strategy: {analysis.next_strategy}")

                # ── Hard stops ────────────────────────────────────────────────
                if self.memory.probe_count >= self.max_probes:
                    queue.put(SessionComplete("Max probe limit reached"))
                    break

                if datetime.datetime.utcnow() >= deadline:
                    queue.put(SessionComplete("Time limit reached"))
                    break

                if self.memory.consecutive_misses >= settings.DIMINISHING_THRESHOLD:
                    queue.put(SessionComplete("Diminishing returns — stopping automatically"))
                    break

                # ── Generate a batch of probes ─────────────────────────────
                probes = attacker.generate_probes(
                    scope_text       = self.scope_text,
                    weak_areas       = self.memory.weak_areas,
                    covered_criteria = self.memory.covered_criteria,
                    key_insights     = self.memory.key_insights,
                    n                = settings.PROBES_PER_BATCH,
                    model            = self.attacker_model,
                )

                for probe_text in probes:
                    if self._stop_event.is_set():
                        break

                    # ── Send to victim ─────────────────────────────────────
                    ok, victim_response = self._victim.send(probe_text)
                    if not ok:
                        victim_response = f"[Error reaching victim: {victim_response}]"

                    # ── Judge response ─────────────────────────────────────
                    j = judge.evaluate(probe_text, victim_response, model=self.judge_model)

                    # ── Update memory ──────────────────────────────────────
                    self.memory.update_from_judgment(
                        vulnerability_found = j.vulnerability_found,
                        weak_area           = j.weak_area,
                        key_insight         = j.key_insight,
                        strategy_tag        = j.strategy_tag,
                    )

                    # ── Write to DB ────────────────────────────────────────
                    probe_id = None
                    try:
                        with get_session() as db:
                            row = ProbeDB(
                                session_id          = self.session_id,
                                probe_text          = probe_text,
                                victim_response     = victim_response,
                                vulnerability_found = j.vulnerability_found,
                                weak_area           = j.weak_area,
                                key_insight         = j.key_insight,
                                severity            = j.severity,
                                strategy_tag        = j.strategy_tag,
                                status              = "judged",
                            )
                            db.add(row)
                            db.flush()
                            probe_id = row.id
                    except Exception as db_err:
                        print(f"[ProbeRunner] DB write error: {db_err}")

                    # ── Push to UI queue ───────────────────────────────────
                    queue.put(ProbeResult(probe_text, victim_response, j, probe_id))

            # ── Finalise session ───────────────────────────────────────────
            try:
                with get_session() as db:
                    sess = db.query(SessionDB).filter_by(session_id=self.session_id).first()
                    if sess:
                        sess.end_time        = datetime.datetime.utcnow()
                        sess.total_probes    = self.memory.probe_count
                        sess.vulnerabilities = self.memory.finding_count
                        sess.status          = "completed"
                        sess.memory_snapshot = self.memory.to_dict()
            except Exception as db_err:
                print(f"[ProbeRunner] Session finalise error: {db_err}")

        except Exception as e:
            queue.put(SessionError(str(e)))
