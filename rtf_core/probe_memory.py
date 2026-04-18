"""
rtf_core/probe_memory.py
------------------------
In-memory state tracker for a single probe session.
Tracks what criteria have been covered, what weak areas were found,
and accumulates key insights for the sidebar memory panel.
"""

import dataclasses
from typing import Optional


@dataclasses.dataclass
class ProbeMemory:
    """
    Mutable snapshot of what the red-team session has learned so far.
    Stored in st.session_state so it persists across Streamlit reruns.
    """
    covered_criteria: list  = dataclasses.field(default_factory=list)
    weak_areas:       list  = dataclasses.field(default_factory=list)
    strong_areas:     list  = dataclasses.field(default_factory=list)
    key_insights:     list  = dataclasses.field(default_factory=list)
    probe_count:      int   = 0
    finding_count:    int   = 0
    consecutive_misses: int = 0   # used for diminishing-returns auto-stop

    # ── Update from a judgment dict ───────────────────────────────────────────

    def update_from_judgment(
        self,
        vulnerability_found: bool,
        weak_area:           Optional[str],
        key_insight:         str,
        strategy_tag:        Optional[str] = None,
    ):
        self.probe_count += 1

        if vulnerability_found:
            self.finding_count    += 1
            self.consecutive_misses = 0
            if weak_area and weak_area not in self.weak_areas:
                self.weak_areas.append(weak_area)
            if key_insight and key_insight not in self.key_insights:
                self.key_insights.append(key_insight)
        else:
            self.consecutive_misses += 1
            # Track as "covered but no vuln" = strong area marker
            if strategy_tag and strategy_tag not in self.strong_areas:
                self.strong_areas.append(f"Resistant to: {strategy_tag}")

        # Always add to covered criteria (deduped by key_insight)
        criterion = weak_area or strategy_tag or "Unknown"
        if criterion and criterion not in self.covered_criteria:
            self.covered_criteria.append(criterion)

    # ── Serialisation ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict:
        return dataclasses.asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "ProbeMemory":
        return cls(**d)

    # ── Coverage % ───────────────────────────────────────────────────────────

    @property
    def coverage_pct(self) -> float:
        """Rough coverage based on unique criteria found vs taxonomy size."""
        from rtf_core.settings import WEAK_AREA_TAXONOMY
        if not WEAK_AREA_TAXONOMY:
            return 0.0
        covered = len(set(self.covered_criteria))
        return min(100.0, (covered / len(WEAK_AREA_TAXONOMY)) * 100)
