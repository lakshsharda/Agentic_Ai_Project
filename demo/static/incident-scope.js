// Shared per-incident scoping helper for the log tab and reasoning feed (Phase 6.2, Task 2).
//
// Polls GET /incidents/scope, keeps a <select id="..."> populated with every incident seen (newest
// first) plus an "all" option, and auto-selects the latest OPEN (non-RESOLVED) incident so a demo does
// not need the presenter to manually filter mid-run -- UNLESS the viewer has picked something
// themselves, in which case their choice sticks until they pick "all" again (which re-arms
// auto-select). Also keeps a header element's text as "currently viewing: incident X (STATUS)" or
// "currently viewing: all traffic", per decision 7's polish requirement.
//
// Plain vanilla JS, no build step, no framework -- same rule as every other page here.
"use strict";

window.IncidentScope = (function () {
  function init({ selectId, headerId, onChange, pollMs = 3000 }) {
    const sel = document.getElementById(selectId);
    const header = headerId ? document.getElementById(headerId) : null;
    let incidents = [];          // last /incidents/scope result, newest first
    let userPicked = false;      // true once the viewer manually changes the dropdown
    let current = "";            // "" = all

    function byId(id) {
      return incidents.find((i) => i.incident_id === id) || null;
    }

    function renderHeader() {
      if (!header) return;
      if (!current) {
        header.textContent = "currently viewing: all traffic";
        header.classList.remove("scoped");
        return;
      }
      const inc = byId(current);
      header.textContent = `currently viewing: incident ${current}${inc ? "  (" + inc.status + ")" : ""}`;
      header.classList.add("scoped");
    }

    function renderOptions() {
      const known = new Set(Array.from(sel.options).map((o) => o.value));
      for (const inc of incidents) {
        const label = `${inc.incident_id}  (${inc.status})`;
        if (!known.has(inc.incident_id)) {
          const o = document.createElement("option");
          o.value = inc.incident_id;
          o.textContent = label;
          sel.appendChild(o);
          known.add(inc.incident_id);
        } else {
          const o = Array.from(sel.options).find((x) => x.value === inc.incident_id);
          if (o && o.textContent !== label) o.textContent = label;
        }
      }
      sel.value = current;
    }

    function setCurrent(id, fromUser) {
      current = id || "";
      if (fromUser) userPicked = true;
      if (!current) userPicked = false;   // picking "all" re-arms auto-select
      sel.value = current;
      renderHeader();
      onChange(current);
    }

    function lockAll() {
      // Like picking "all" from the dropdown, but stays locked against auto-select (deep-linking with
      // ?incident_id=all, or a screenshot/test that wants the unscoped view and nothing else).
      current = "";
      userPicked = true;
      sel.value = "";
      renderHeader();
      onChange("");
    }

    sel.addEventListener("change", () => setCurrent(sel.value, true));

    async function poll() {
      try {
        const r = await fetch("/incidents/scope?limit=20", { cache: "no-store" });
        const d = await r.json();
        if (d.ok) {
          incidents = d.incidents;
          renderOptions();
          renderHeader();
          if (!userPicked) {
            const latestOpen = incidents.find((i) => i.open);
            if (latestOpen && latestOpen.incident_id !== current) {
              setCurrent(latestOpen.incident_id, false);
            }
          }
        }
      } catch (e) { /* demo tool; a transient fetch error here is not worth surfacing */ }
      setTimeout(poll, pollMs);
    }
    poll();

    return {
      get current() { return current; },
      list: () => incidents,
      byId,
      setCurrent: (id) => setCurrent(id, true),
      lockAll,
    };
  }

  return { init };
})();
