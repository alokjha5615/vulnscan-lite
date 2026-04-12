import React, { useState, useEffect } from "react";
import "./App.css";

function App() {
  const [url, setUrl] = useState("");
  const [scanId, setScanId] = useState("");
  const [status, setStatus] = useState("");
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState([]);

  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

  const loadHistory = async () => {
    try {
      const response = await fetch(`${BACKEND_URL}/api/history`);
      const data = await response.json();
      setHistory(data.history || []);
    } catch (err) {
      console.error("Failed to load history");
    }
  };

  const formatDateTime = (isoString) => {
    if (!isoString) return "N/A";

    const date = new Date(isoString);

    return date.toLocaleString("en-IN", {
      year: "numeric",
      month: "short",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: "2-digit"
    });
  };

  const getGaugeColor = (score) => {
    if (score >= 80) return "#22c55e";
    if (score >= 60) return "#38bdf8";
    if (score >= 40) return "#f59e0b";
    return "#ef4444";
  };

  const downloadPdf = () => {
    if (!scanId) return;
    window.open(`${BACKEND_URL}/api/scan/${scanId}/pdf`, "_blank");
  };

  const startScan = async () => {
    setError("");
    setResult(null);
    setScanId("");
    setStatus("");
    setLoading(true);

    try {
      const response = await fetch(`${BACKEND_URL}/api/scan`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({ url })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(
          data.error ||
          data.detail ||
          data.message ||
          "Failed to start scan"
        );
      }

      setScanId(data.scan_id);
      setStatus(data.status);
    } catch (err) {
      setError(err.message);
      setLoading(false);
    }
  };

  useEffect(() => {
    loadHistory();
  }, []);

  useEffect(() => {
    if (!scanId) return;

    const interval = setInterval(async () => {
      try {
        const res = await fetch(`${BACKEND_URL}/api/scan/${scanId}/status`);
        const data = await res.json();

        setStatus(data.status);

        if (data.status === "completed") {
          const resultRes = await fetch(`${BACKEND_URL}/api/scan/${scanId}/result`);
          const resultData = await resultRes.json();

          setResult(resultData.result);
          setLoading(false);
          clearInterval(interval);
          loadHistory();
        }

        if (data.status === "failed") {
          setError("Scan failed");
          setLoading(false);
          clearInterval(interval);
        }
      } catch (err) {
        setError("Error fetching scan status");
        setLoading(false);
        clearInterval(interval);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, BACKEND_URL]);

  const recentHistory = history.slice().reverse().slice(0, 6);

  return (
    <div className="app">
      <div className="container">
        <h1>VulnScan Lite 🔍</h1>
        <p className="subtitle">On-Demand Web Vulnerability Scanner</p>

        <div className="disclaimer">
          Only scan websites you own or are authorized to test.
        </div>

        <div className="scan-box">
          <input
            type="text"
            placeholder="Enter URL (e.g. google.com)"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
          />
          <button onClick={startScan} disabled={loading}>
            {loading ? "Scanning..." : "Start Scan"}
          </button>
        </div>

        {status && (
          <div className="status-box">
            <strong>Status:</strong> {status}
          </div>
        )}

        {error && <p style={{ color: "red" }}>{error}</p>}

        {result && (
          <div className="result-box">
            <div className="summary-card">
              <div className="summary-top">
                <div className="summary-info">
                  <p><strong>Target:</strong> {result.target}</p>
                  <p className="grade">Grade: {result.summary.grade}</p>
                  <p><strong>Total Findings:</strong> {result.summary.total_findings}</p>

                  <button className="pdf-button" onClick={downloadPdf}>
                    Download PDF Report
                  </button>
                </div>

                <div
                  className="gauge"
                  style={{
                    "--score": result.summary.score,
                    "--gauge-color": getGaugeColor(result.summary.score)
                  }}
                >
                  <div className="gauge-inner">
                    <div className="gauge-score">{result.summary.score}</div>
                    <div className="gauge-label">Score</div>
                  </div>
                </div>
              </div>
            </div>

            <div className="checks-section">
              <div className="checks-card">
                <h3>Passed Checks</h3>
                <ul>
                  {result.summary.passed_checks.map((item, i) => (
                    <li key={i} className="pass">{item}</li>
                  ))}
                </ul>
              </div>

              <div className="checks-card">
                <h3>Failed Checks</h3>
                <ul>
                  {result.summary.failed_checks.map((item, i) => (
                    <li key={i} className="fail">{item}</li>
                  ))}
                </ul>
              </div>
            </div>

            <div className="findings-section">
              <h2>Detailed Findings</h2>

              {result.modules.map((module, moduleIndex) => (
                <div key={moduleIndex} className="module-card">
                  <h3 className="module-title">
                    {module.category.replace("_", " ")}
                  </h3>

                  {module.findings.map((finding, findingIndex) => (
                    <div key={findingIndex} className="finding-item">
                      <p>
                        <span className="finding-label">Check:</span>{" "}
                        {finding.check_name}
                      </p>

                      <p>
                        <span className="finding-label">Status:</span>{" "}
                        <span
                          className={
                            finding.status === "pass"
                              ? "finding-status-pass"
                              : finding.status === "fail"
                              ? "finding-status-fail"
                              : "finding-status-info"
                          }
                        >
                          {finding.status}
                        </span>
                      </p>

                      <p>
                        <span className="finding-label">Details:</span>{" "}
                        {finding.details}
                      </p>

                      <div
                        className={`severity-badge severity-${finding.severity?.toLowerCase?.() || "info"}`}
                      >
                        Severity: {finding.severity}
                      </div>

                      <p>
                        <span className="finding-label">Remediation:</span>{" "}
                        {finding.remediation}
                      </p>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        )}

        <div className="history-section">
          <h2>Recent Scan History</h2>

          {recentHistory.length === 0 ? (
            <div className="history-empty">No scans yet.</div>
          ) : (
            <div className="history-list">
              {recentHistory.map((item, index) => (
                <div key={index} className="history-card">
                  <p><strong>Target:</strong> {item.target}</p>
                  <p><strong>Score:</strong> {item.score}</p>
                  <p><strong>Grade:</strong> {item.grade}</p>
                  <p><strong>Completed:</strong> {formatDateTime(item.completed_at)}</p>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

export default App;