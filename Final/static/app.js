// static/app.js

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const startBtn = document.getElementById("startBtn");
    const scopeInput = document.getElementById("targetScope");
    const endpointInput = document.getElementById("targetEndpoint");
    
    // Status Elements
    const labelProbes = document.querySelector(".label-probes");
    const labelCoverage = document.querySelector(".label-coverage");
    const weakAreasList = document.getElementById("weakAreasList");
    const strongAreasList = document.getElementById("strongAreasList");
    const feedContainer = document.getElementById("feedContainer");
    const feedStatus = document.getElementById("feedStatus");
    
    // State
    let isRunning = false;
    let pollInterval = null;
    let knownProbeIds = new Set();
    let isFetchingStatus = false; // Prevent overlapping fetch calls

    // API Handlers
    startBtn.addEventListener("click", async () => {
        if (isRunning) {
            stopPolling();
            return;
        }

        const scope = scopeInput.value.trim();
        const endpoint = endpointInput.value.trim() || null;

        if (!scope) {
            alert("Scope is required.");
            return;
        }

        setRunningState(true);

        try {
            const resp = await fetch("/probes/start", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    scope_text: scope,
                    target_endpoint: endpoint
                })
            });
            
            if (!resp.ok) throw new Error("Failed to start session");
            
            // Clear feed on start
            feedContainer.innerHTML = "";
            knownProbeIds.clear();

            // Begin polling status continuously
            pollInterval = setInterval(fetchStatusLoop, 2000);
        } catch (error) {
            console.error(error);
            alert("Error starting probe session.");
            setRunningState(false);
        }
    });

    async function fetchStatusLoop() {
        if (isFetchingStatus) return;
        isFetchingStatus = true;
        
        try {
            const resp = await fetch("/probes/status");
            if (resp.ok) {
                const data = await resp.json();
                updateDashboard(data);
                
                // Keep polling until it's done or we reach limit
                if (data.is_complete && isRunning) {
                    stopPolling();
                }
            }
        } catch (e) {
            console.error("Polling error", e);
        } finally {
            isFetchingStatus = false;
        }
    }

    function updateDashboard(data) {
        // Update Metrics
        animateValueChange(labelProbes, data.total_probes.toString());
        animateValueChange(labelCoverage, data.coverage_percentage.toFixed(1) + "%");

        // Update Tags
        renderTags(weakAreasList, data.weak_areas, "weak");
        renderTags(strongAreasList, data.strong_areas, "strong");

        // Render Probes
        if (data.probes && data.probes.length > 0) {
            // Remove empty state message if it exists
            const emptyState = feedContainer.querySelector(".empty-feed");
            if (emptyState) emptyState.remove();

            data.probes.forEach(probe => {
                if (!knownProbeIds.has(probe.probe_id)) {
                    appendProbe(probe);
                    knownProbeIds.add(probe.probe_id);
                }
            });
        }
    }

    function appendProbe(probe) {
        const div = document.createElement("div");
        div.className = "probe-card";
        
        const timeStr = new Date(probe.timestamp).toLocaleTimeString();
        
        let targetList = "";
        if (probe.criteria_covered && probe.criteria_covered.length > 0) {
            targetList = ` | Tags: ${probe.criteria_covered.join(", ")}`;
        }

        const victimContentHtml = probe.victim_response ? 
            `<div class="victim-response">
                <span>Victim Response:</span>
                <div class="victim-response-text">${probe.victim_response.substring(0, 300) + (probe.victim_response.length > 300 ? '...' : '')}</div>
             </div>` : '';

        div.innerHTML = `
            <div class="probe-header">
                <div>[${probe.probe_id.split("-")[0]}] ${timeStr}</div>
                <div>Criteria Generated</div>
            </div>
            <div class="probe-content">
                ${probe.probe_text}
            </div>
            ${victimContentHtml}
        `;
        
        feedContainer.prepend(div); // Add to top of feed
    }

    function renderTags(container, tags, type) {
        if (!tags || tags.length === 0) {
            container.innerHTML = `<li class="empty-state">No ${type} areas yet...</li>`;
            return;
        }
        
        // Only update if changed visually to prevent animation flicker (simplified mapping)
        const newHtml = tags.map(t => `<li class="tag ${type === 'strong' ? 'strong' : ''}">${t}</li>`).join("");
        if (container.innerHTML !== newHtml) {
            container.innerHTML = newHtml;
        }
    }

    function setRunningState(running) {
        isRunning = running;
        if (running) {
            startBtn.textContent = "Stop Session";
            startBtn.classList.add("running");
            feedStatus.textContent = "Live Simulation Active";
            feedStatus.classList.add("live");
        } else {
            startBtn.textContent = "Launch Red Team";
            startBtn.classList.remove("running");
            feedStatus.textContent = "Idle";
            feedStatus.classList.remove("live");
        }
    }

    function stopPolling() {
        if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
        }
        setRunningState(false);
    }

    // Little helper to pop the number text
    function animateValueChange(el, newValue) {
        if (el.textContent !== newValue) {
            el.textContent = newValue;
            el.style.transform = "scale(1.2)";
            el.style.color = "#fff";
            setTimeout(() => {
                el.style.transform = "scale(1)";
                el.style.color = "";
            }, 200);
        }
    }
});
