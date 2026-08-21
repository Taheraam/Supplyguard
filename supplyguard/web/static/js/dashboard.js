/**
 * SupplyGuard Dashboard Client Scripts (Chart.js + Table Filtering)
 */

document.addEventListener('DOMContentLoaded', () => {
  const scanDataEl = document.getElementById('scan-meta');
  if (scanDataEl) {
    const scanId = scanDataEl.dataset.scanId;
    loadScanCharts(scanId);
  }

  setupTableFilters();
});

async function loadScanCharts(scanId) {
  try {
    const res = await fetch(`/api/scans/${scanId}`);
    if (!res.ok) return;
    const data = await res.json();

    renderRiskGauge(data.risk_score);
    renderSourcePie(data.source_breakdown);
    renderSeverityBar(data.severity_breakdown);
  } catch (err) {
    console.error("Failed to load chart data:", err);
  }
}

function renderRiskGauge(score) {
  const ctx = document.getElementById('riskScoreChart');
  if (!ctx) return;

  let color = '#10b981';
  if (score >= 25 && score < 50) color = '#eab308';
  else if (score >= 50 && score < 75) color = '#f97316';
  else if (score >= 75) color = '#ef4444';

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Risk Score', 'Remaining Headroom'],
      datasets: [{
        data: [score, Math.max(0, 100 - score)],
        backgroundColor: [color, 'rgba(255, 255, 255, 0.05)'],
        borderWidth: 0,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      circumference: 180,
      rotation: -90,
      cutout: '75%',
      plugins: {
        legend: { display: false },
        tooltip: { enabled: true }
      }
    }
  });
}

function renderSourcePie(sources) {
  const ctx = document.getElementById('sourcePieChart');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['SBOM (OSV)', 'Secrets', 'SAST (AI Smells)'],
      datasets: [{
        data: [
          sources.sbom_osv || 0,
          sources.secrets || 0,
          sources.sast || 0
        ],
        backgroundColor: ['#06b6d4', '#f43f5e', '#8b5cf6'],
        borderWidth: 1,
        borderColor: '#111827'
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'bottom',
          labels: { color: '#9ca3af', boxWidth: 12 }
        }
      }
    }
  });
}

function renderSeverityBar(severities) {
  const ctx = document.getElementById('severityBarChart');
  if (!ctx) return;

  new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Critical', 'High', 'Medium', 'Low'],
      datasets: [{
        label: 'Findings',
        data: [
          severities.CRITICAL || 0,
          severities.HIGH || 0,
          severities.MEDIUM || 0,
          severities.LOW || 0
        ],
        backgroundColor: ['#ef4444', '#f97316', '#eab308', '#10b981'],
        borderRadius: 4
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: { display: false }
      },
      scales: {
        x: {
          ticks: { color: '#9ca3af' },
          grid: { display: false }
        },
        y: {
          ticks: { color: '#9ca3af', precision: 0 },
          grid: { color: 'rgba(255, 255, 255, 0.05)' }
        }
      }
    }
  });
}

function setupTableFilters() {
  const searchInput = document.getElementById('tableSearch');
  const sevSelect = document.getElementById('severityFilter');
  const srcSelect = document.getElementById('sourceFilter');
  const rows = document.querySelectorAll('#findingsTable tbody tr');

  function filterRows() {
    const q = (searchInput?.value || '').toLowerCase();
    const sev = (sevSelect?.value || 'ALL').toUpperCase();
    const src = (srcSelect?.value || 'ALL').toLowerCase();

    rows.forEach(row => {
      const text = row.textContent.toLowerCase();
      const rowSev = (row.dataset.severity || '').toUpperCase();
      const rowSrc = (row.dataset.source || '').toLowerCase();

      const matchQ = !q || text.includes(q);
      const matchSev = sev === 'ALL' || rowSev === sev;
      const matchSrc = src === 'ALL' || rowSrc === src;

      row.style.display = (matchQ && matchSev && matchSrc) ? '' : 'none';
    });
  }

  searchInput?.addEventListener('input', filterRows);
  sevSelect?.addEventListener('change', filterRows);
  srcSelect?.addEventListener('change', filterRows);
}
