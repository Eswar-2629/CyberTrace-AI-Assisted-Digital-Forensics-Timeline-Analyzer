const token = localStorage.getItem("cybertrace_token");

if (!token) {
    window.location.href = "/";
}

const user = JSON.parse(
    localStorage.getItem("cybertrace_user") || "{}"
);

document.querySelector("#currentUser").textContent =
    `${user.username || "user"} (${user.role || "unknown"})`;

let timeline;
let classificationChart;

function authHeaders() {
    return {
        "Authorization": `Bearer ${token}`
    };
}

async function api(path, options = {}) {
    const response = await fetch(path, {
        ...options,
        headers: {
            ...authHeaders(),
            ...(options.headers || {})
        }
    });

    if (response.status === 401) {
        localStorage.clear();
        window.location.href = "/";
    }

    return response;
}

async function loadCases() {
    const response = await api("/api/cases");

    if (!response.ok) {
        throw new Error("Unable to load cases");
    }

    const cases = await response.json();
    const select = document.querySelector("#caseSelect");
    select.replaceChildren();

    for (const item of cases) {
        const option = document.createElement("option");
        option.value = item.id;
        option.textContent = `${item.case_number} — ${item.title}`;
        select.appendChild(option);
    }

    if (cases.length > 0) {
        await loadTimeline();
    }
}

function renderTimeline(events) {
    const container = document.querySelector("#timeline");

    const items = new vis.DataSet(events.map(event => ({
        id: event.id,
        start: event.start,
        content: event.content,
        className: event.is_anomaly ? "anomaly" : "",
        title: event.message
    })));

    if (timeline) {
        timeline.destroy();
    }

    timeline = new vis.Timeline(
        container,
        items,
        {
            zoomable: true,
            moveable: true,
            stack: true,
            orientation: "top",
            tooltip: {
                followMouse: true
            }
        }
    );
}

function renderChart(events) {
    const counts = {};

    for (const event of events) {
        const key = event.classification || "UNKNOWN";
        counts[key] = (counts[key] || 0) + 1;
    }

    if (classificationChart) {
        classificationChart.destroy();
    }

    classificationChart = new Chart(
        document.querySelector("#classificationChart"),
        {
            type: "bar",
            data: {
                labels: Object.keys(counts),
                datasets: [{
                    label: "Events",
                    data: Object.values(counts)
                }]
            },
            options: {
                responsive: true,
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            precision: 0
                        }
                    }
                }
            }
        }
    );
}

function renderAnomalyTable(events) {
    const body = document.querySelector("#anomalyTable");
    body.replaceChildren();

    for (const event of events.filter(item => item.is_anomaly)) {
        const row = document.createElement("tr");

        const values = [
            new Date(event.start).toLocaleString(),
            event.classification || event.event_type,
            event.message
        ];

        for (const value of values) {
            const cell = document.createElement("td");
            cell.textContent = value;
            row.appendChild(cell);
        }

        body.appendChild(row);
    }
}

async function loadTimeline() {
    const caseId = document.querySelector("#caseSelect").value;

    if (!caseId) {
        return;
    }

    const anomaliesOnly =
        document.querySelector("#anomaliesOnly").checked;

    const response = await api(
        `/api/events/cases/${caseId}/timeline?anomalies_only=${anomaliesOnly}`
    );

    if (!response.ok) {
        throw new Error("Unable to load timeline");
    }

    const data = await response.json();
    const events = data.events;

    document.querySelector("#eventCount").textContent = events.length;
    document.querySelector("#anomalyCount").textContent =
        events.filter(item => item.is_anomaly).length;
    document.querySelector("#classificationCount").textContent =
        new Set(events.map(item => item.classification)).size;

    renderTimeline(events);
    renderChart(events);
    renderAnomalyTable(events);
}

document.querySelector("#caseSelect").addEventListener(
    "change",
    loadTimeline
);

document.querySelector("#refreshButton").addEventListener(
    "click",
    loadTimeline
);

document.querySelector("#anomaliesOnly").addEventListener(
    "change",
    loadTimeline
);

document.querySelector("#exportButton").addEventListener(
    "click",
    () => {
        const caseId = document.querySelector("#caseSelect").value;
        window.open(
            `/api/reports/cases/${caseId}`,
            "_blank"
        );
    }
);

document.querySelector("#logoutButton").addEventListener(
    "click",
    () => {
        localStorage.clear();
        window.location.href = "/";
    }
);

loadCases().catch(error => {
    console.error(error);
});