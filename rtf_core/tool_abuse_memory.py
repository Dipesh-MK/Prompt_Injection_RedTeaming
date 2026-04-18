"""
rtf_core/tool_abuse_memory.py
-----------------------------
Specialized memory layer for agentic tool abuse testing.
Tracks per-vector success rates, per-tool vulnerability scores,
and uses Thompson Sampling for intelligent probe selection.
"""

import random
import math
import dataclasses
from typing import Optional
from dataclasses import dataclass, field


TOOL_ABUSE_VECTORS = [
    "indirect_injection",
    "parameter_poisoning",
    "tool_chaining",
    "scope_escalation",
    "exfiltration",
]

DEFAULT_TOOLS = [
    "check_balance",
    "get_transaction_history",
    "transfer_funds",
    "update_profile",
    "send_notification",
    "execute_query",
]


@dataclass
class VectorStats:
    """Beta distribution parameters for Thompson Sampling."""
    alpha: float = 1.0   # successes + 1 (prior)
    beta: float = 1.0    # failures + 1 (prior)
    probes_sent: int = 0
    hits: int = 0
    max_severity: float = 0.0
    last_successful_probe: Optional[str] = None

    @property
    def success_rate(self) -> float:
        total = self.alpha + self.beta - 2  # subtract priors
        if total <= 0:
            return 0.0
        return (self.alpha - 1) / total

    def sample(self) -> float:
        """Sample from beta distribution for Thompson Sampling."""
        return random.betavariate(self.alpha, self.beta)

    def record_hit(self, severity: float = 0.5, probe_text: str = ""):
        self.alpha += 1
        self.hits += 1
        self.probes_sent += 1
        self.max_severity = max(self.max_severity, severity)
        if probe_text:
            self.last_successful_probe = probe_text

    def record_miss(self):
        self.beta += 1
        self.probes_sent += 1


@dataclass
class ToolVulnScore:
    """Track how vulnerable a specific tool is."""
    tool_name: str
    probes_targeting: int = 0
    successful_abuses: int = 0
    highest_severity: float = 0.0
    abuse_types: list = field(default_factory=list)

    @property
    def vuln_score(self) -> float:
        if self.probes_targeting == 0:
            return 0.0
        return self.successful_abuses / self.probes_targeting


@dataclass
class ConversationTurn:
    """Single turn in a multi-turn attack conversation."""
    turn_number: int
    probe_text: str
    response_text: str
    tool_calls_detected: list = field(default_factory=list)
    vulnerability_found: bool = False
    severity: float = 0.0
    vector: str = ""
    timestamp: str = ""


@dataclass
class ToolAbuseMemory:
    """
    Full memory state for a tool abuse testing session.
    Uses Thompson Sampling to intelligently pick next attack vectors.
    """
    # Per-vector stats for Thompson Sampling
    vector_stats: dict = field(default_factory=dict)

    # Per-tool vulnerability tracking
    tool_scores: dict = field(default_factory=dict)

    # Conversation turns (multi-turn history)
    conversation_turns: list = field(default_factory=list)

    # Global counters
    total_probes: int = 0
    total_hits: int = 0
    total_conversations: int = 0
    consecutive_misses: int = 0

    # Discovered patterns
    weak_vectors: list = field(default_factory=list)
    strong_vectors: list = field(default_factory=list)
    key_findings: list = field(default_factory=list)
    discovered_tool_chains: list = field(default_factory=list)

    # Configuration
    available_tools: list = field(default_factory=list)
    enabled_vectors: list = field(default_factory=list)

    def initialize(self, tools: list = None, vectors: list = None):
        """Initialize memory with available tools and vectors."""
        self.available_tools = tools or list(DEFAULT_TOOLS)
        self.enabled_vectors = vectors or list(TOOL_ABUSE_VECTORS)

        for vec in self.enabled_vectors:
            if vec not in self.vector_stats:
                self.vector_stats[vec] = VectorStats()

        for tool in self.available_tools:
            if tool not in self.tool_scores:
                self.tool_scores[tool] = ToolVulnScore(tool_name=tool)

    # ---- Thompson Sampling probe selection ----

    def suggest_next_vector(self) -> str:
        """
        Use Thompson Sampling to select the next attack vector.
        Balances exploration of untested vectors with exploitation of successful ones.
        """
        if not self.vector_stats:
            self.initialize()

        best_vector = None
        best_sample = -1.0

        for vec_name, stats in self.vector_stats.items():
            if vec_name not in self.enabled_vectors:
                continue
            sample = stats.sample()
            if sample > best_sample:
                best_sample = sample
                best_vector = vec_name

        return best_vector or random.choice(self.enabled_vectors)

    def suggest_target_tool(self) -> Optional[str]:
        """Suggest which tool to target next based on vulnerability scores."""
        if not self.tool_scores:
            return None

        # Prefer under-tested tools, then vulnerable tools
        untested = [t for t, s in self.tool_scores.items() if s.probes_targeting == 0]
        if untested:
            return random.choice(untested)

        # Weight by inverse of testing + vulnerability score
        weighted = []
        for tool_name, score in self.tool_scores.items():
            weight = score.vuln_score * 2 + (1.0 / (score.probes_targeting + 1))
            weighted.append((tool_name, weight))

        weighted.sort(key=lambda x: x[1], reverse=True)
        # Pick from top 3 with some randomness
        top = weighted[:min(3, len(weighted))]
        return random.choice(top)[0]

    # ---- Recording results ----

    def record_probe_result(
        self,
        vector: str,
        probe_text: str,
        response_text: str,
        vulnerability_found: bool,
        severity: float = 0.0,
        tool_calls: list = None,
        turn_number: int = 0,
    ):
        """Record a single probe result and update all statistics."""
        self.total_probes += 1

        # Update vector stats
        if vector in self.vector_stats:
            if vulnerability_found:
                self.vector_stats[vector].record_hit(severity, probe_text)
            else:
                self.vector_stats[vector].record_miss()

        # Update tool scores
        if tool_calls:
            for tc in tool_calls:
                tool_name = tc.get("tool_name", "")
                if tool_name in self.tool_scores:
                    ts = self.tool_scores[tool_name]
                    ts.probes_targeting += 1
                    if vulnerability_found:
                        ts.successful_abuses += 1
                        ts.highest_severity = max(ts.highest_severity, severity)
                        abuse_type = tc.get("abuse_type", vector)
                        if abuse_type not in ts.abuse_types:
                            ts.abuse_types.append(abuse_type)

        # Update global counters
        if vulnerability_found:
            self.total_hits += 1
            self.consecutive_misses = 0
            if vector not in self.weak_vectors:
                self.weak_vectors.append(vector)
        else:
            self.consecutive_misses += 1
            if (
                vector not in self.strong_vectors
                and self.vector_stats.get(vector, VectorStats()).probes_sent >= 3
                and self.vector_stats.get(vector, VectorStats()).hits == 0
            ):
                self.strong_vectors.append(vector)

        # Record conversation turn
        turn = ConversationTurn(
            turn_number=turn_number,
            probe_text=probe_text,
            response_text=response_text[:500],
            tool_calls_detected=tool_calls or [],
            vulnerability_found=vulnerability_found,
            severity=severity,
            vector=vector,
        )
        self.conversation_turns.append(turn)

    def record_finding(self, finding: str):
        """Record a key finding."""
        if finding and finding not in self.key_findings:
            self.key_findings.append(finding)

    def record_tool_chain(self, chain: list):
        """Record a discovered tool chain vulnerability."""
        chain_str = " -> ".join(chain)
        if chain_str not in self.discovered_tool_chains:
            self.discovered_tool_chains.append(chain_str)

    # ---- Smart mutation suggestions ----

    def suggest_probe_mutation(self, probe_text: str, vector: str) -> dict:
        """
        Suggest how to mutate a probe based on what we have learned.
        Returns a dict of mutation parameters.
        """
        suggestions = {
            "increase_indirection": False,
            "combine_vectors": [],
            "target_weak_tools": [],
            "escalate_payload": False,
            "use_multi_turn": False,
        }

        # If this vector has been successful, suggest combining with others
        stats = self.vector_stats.get(vector, VectorStats())
        if stats.hits > 0:
            other_weak = [v for v in self.weak_vectors if v != vector]
            if other_weak:
                suggestions["combine_vectors"] = other_weak[:2]

        # If we've seen refusals, suggest increasing indirection
        if stats.probes_sent > 2 and stats.success_rate < 0.3:
            suggestions["increase_indirection"] = True

        # Suggest tools that have shown vulnerability
        weak_tools = [
            t for t, s in self.tool_scores.items()
            if s.vuln_score > 0.3
        ]
        suggestions["target_weak_tools"] = weak_tools

        # After several turns, suggest escalation
        if len(self.conversation_turns) >= 3:
            suggestions["escalate_payload"] = True

        # If single-turn hasn't worked, try multi-turn
        if stats.probes_sent >= 3 and stats.hits == 0:
            suggestions["use_multi_turn"] = True

        return suggestions

    # ---- Coverage metrics ----

    @property
    def vector_coverage(self) -> float:
        """Percentage of vectors that have been tested."""
        if not self.enabled_vectors:
            return 0.0
        tested = sum(
            1 for v in self.enabled_vectors
            if self.vector_stats.get(v, VectorStats()).probes_sent > 0
        )
        return (tested / len(self.enabled_vectors)) * 100

    @property
    def tool_coverage(self) -> float:
        """Percentage of tools that have been targeted."""
        if not self.available_tools:
            return 0.0
        tested = sum(
            1 for t in self.available_tools
            if self.tool_scores.get(t, ToolVulnScore("")).probes_targeting > 0
        )
        return (tested / len(self.available_tools)) * 100

    @property
    def overall_vuln_rate(self) -> float:
        if self.total_probes == 0:
            return 0.0
        return self.total_hits / self.total_probes

    # ---- Serialization ----

    def to_dict(self) -> dict:
        """Serialize to dict for session persistence."""
        return {
            "vector_stats": {
                k: dataclasses.asdict(v) for k, v in self.vector_stats.items()
            },
            "tool_scores": {
                k: dataclasses.asdict(v) for k, v in self.tool_scores.items()
            },
            "total_probes": self.total_probes,
            "total_hits": self.total_hits,
            "total_conversations": self.total_conversations,
            "consecutive_misses": self.consecutive_misses,
            "weak_vectors": self.weak_vectors,
            "strong_vectors": self.strong_vectors,
            "key_findings": self.key_findings,
            "discovered_tool_chains": self.discovered_tool_chains,
            "available_tools": self.available_tools,
            "enabled_vectors": self.enabled_vectors,
            "conversation_turns": [dataclasses.asdict(t) for t in self.conversation_turns[-50:]],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ToolAbuseMemory":
        mem = cls()
        mem.total_probes = d.get("total_probes", 0)
        mem.total_hits = d.get("total_hits", 0)
        mem.total_conversations = d.get("total_conversations", 0)
        mem.consecutive_misses = d.get("consecutive_misses", 0)
        mem.weak_vectors = d.get("weak_vectors", [])
        mem.strong_vectors = d.get("strong_vectors", [])
        mem.key_findings = d.get("key_findings", [])
        mem.discovered_tool_chains = d.get("discovered_tool_chains", [])
        mem.available_tools = d.get("available_tools", [])
        mem.enabled_vectors = d.get("enabled_vectors", [])

        for k, v in d.get("vector_stats", {}).items():
            mem.vector_stats[k] = VectorStats(**v)
        for k, v in d.get("tool_scores", {}).items():
            mem.tool_scores[k] = ToolVulnScore(**v)

        return mem
