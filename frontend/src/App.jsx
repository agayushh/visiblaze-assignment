import React, { useState, useEffect, useCallback } from 'react';
import { 
  ShieldCheck, 
  Server, 
  Database, 
  CheckCircle2, 
  XCircle,
  RefreshCw,
  Play
} from 'lucide-react';
import './index.css';

const API_BASE_URL = window.API_BASE_URL || "https://wlw41u79sc.execute-api.us-east-1.amazonaws.com/Prod";

function App() {
  const [activeTab, setActiveTab] = useState('ec2');
  
  // Data States
  const [ec2Data, setEc2Data] = useState([]);
  const [s3Data, setS3Data] = useState([]);
  const [cisData, setCisData] = useState([]);
  
  // Loading States
  const [ec2Loading, setEc2Loading] = useState(false);
  const [s3Loading, setS3Loading] = useState(false);
  const [cisLoading, setCisLoading] = useState(false);
  
  // Error States
  const [ec2Error, setEc2Error] = useState(null);
  const [s3Error, setS3Error] = useState(null);
  const [cisError, setCisError] = useState(null);
  
  // Global States
  const [scanStatus, setScanStatus] = useState({ state: '', text: 'Ready' });
  const [isScanning, setIsScanning] = useState(false);
  const [toast, setToast] = useState({ show: false, msg: '', type: 'info' });

  // Helpers
  const showToast = useCallback((msg, type = 'info', duration = 3500) => {
    setToast({ show: true, msg, type });
    setTimeout(() => {
      setToast(prev => ({ ...prev, show: false }));
    }, duration);
  }, []);

  const formatTimestamp = (ts) => {
    if (!ts) return "—";
    try {
      return new Date(ts).toLocaleString(undefined, {
        dateStyle: "short",
        timeStyle: "medium",
      });
    } catch { return ts; }
  };

  const apiFetch = useCallback(async (path) => {
    const res = await fetch(`${API_BASE_URL}${path}`);
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    return res.json();
  }, []);

  // Data Fetchers
  const loadEC2 = useCallback(async () => {
    setEc2Loading(true);
    setEc2Error(null);
    try {
      const data = await apiFetch("/instances");
      const instances = data.instances || data || [];
      setEc2Data(instances);
      showToast(`Loaded ${instances.length} EC2 instance(s)`, "success");
    } catch (err) {
      console.error("EC2 load error:", err);
      setEc2Error(`Failed to load EC2 instances: ${err.message}`);
      setEc2Data([]);
      showToast("EC2 load failed – check console", "error");
    } finally {
      setEc2Loading(false);
    }
  }, [apiFetch, showToast]);

  const loadS3 = useCallback(async () => {
    setS3Loading(true);
    setS3Error(null);
    try {
      const data = await apiFetch("/buckets");
      const buckets = data.buckets || data || [];
      setS3Data(buckets);
      showToast(`Loaded ${buckets.length} S3 bucket(s)`, "success");
    } catch (err) {
      console.error("S3 load error:", err);
      setS3Error(`Failed to load S3 buckets: ${err.message}`);
      setS3Data([]);
      showToast("S3 load failed – check console", "error");
    } finally {
      setS3Loading(false);
    }
  }, [apiFetch, showToast]);

  const loadCIS = useCallback(async () => {
    setCisLoading(true);
    setCisError(null);
    try {
      const data = await apiFetch("/cis-results");
      const results = data.results || data || [];
      setCisData(results);
      
      const failed = results.filter((r) => r.status === "FAIL").length;
      showToast(
        `Loaded ${results.length} check(s) — ${failed} failed`,
        failed > 0 ? "error" : "success"
      );
    } catch (err) {
      console.error("CIS load error:", err);
      setCisError(`Failed to load CIS results: ${err.message}`);
      setCisData([]);
      showToast("CIS load failed – check console", "error");
    } finally {
      setCisLoading(false);
    }
  }, [apiFetch, showToast]);

  const runScan = async () => {
    setIsScanning(true);
    setScanStatus({ state: 'scanning', text: 'Scanning…' });
    showToast("Full scan started – this may take 30–60 seconds", "info", 8000);

    try {
      const res = await fetch(`${API_BASE_URL}/scan`, { method: "POST" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const data = await res.json();

      const summary = data.summary || {};
      showToast(
        `Scan complete! ${summary.total || 0} checks — ${summary.passed || 0} passed, ${summary.failed || 0} failed`,
        summary.failed > 0 ? "error" : "success",
        6000
      );
      setScanStatus({ state: '', text: 'Scan complete' });

      // Refresh all panels
      await Promise.all([loadEC2(), loadS3(), loadCIS()]);
    } catch (err) {
      console.error("Scan error:", err);
      showToast(`Scan failed: ${err.message}`, "error");
      setScanStatus({ state: 'error', text: 'Scan failed' });
    } finally {
      setIsScanning(false);
      setTimeout(() => setScanStatus({ state: '', text: 'Ready' }), 4000);
    }
  };

  // Initial Load
  useEffect(() => {
    loadEC2();
    loadS3();
    loadCIS();
  }, [loadEC2, loadS3, loadCIS]);

  // Derived Summary Stats
  const passCount = cisData.filter(r => r.status === 'PASS').length;
  const failCount = cisData.filter(r => r.status === 'FAIL').length;

  return (
    <>
      <header>
        <div className="header-inner">
          <div className="brand">
            <div className="brand-icon">
              <ShieldCheck />
            </div>
            <div>
              <h1>Cloud Posture Scanner</h1>
              <div className="brand-sub">AWS Security Assessment</div>
            </div>
          </div>
          <div className="header-actions">
            <div className="scan-status">
              <div className={`status-dot ${scanStatus.state}`}></div>
              <span className="status-text">{scanStatus.text}</span>
            </div>
            <button 
              className="btn-scan" 
              onClick={runScan} 
              disabled={isScanning}
            >
              <Play size={15} />
              Run New Scan
            </button>
          </div>
        </div>
      </header>

      <div className="container summary-section">
        <div className="summary-grid">
          <div className="summary-card">
            <div className="card-icon ec2-icon"><Server /></div>
            <div className="card-body">
              <div className="card-label">EC2 Instances</div>
              <div className="card-value">{ec2Data.length}</div>
            </div>
          </div>
          <div className="summary-card">
            <div className="card-icon s3-icon"><Database /></div>
            <div className="card-body">
              <div className="card-label">S3 Buckets</div>
              <div className="card-value">{s3Data.length}</div>
            </div>
          </div>
          <div className="summary-card">
            <div className="card-icon pass-icon"><CheckCircle2 /></div>
            <div className="card-body">
              <div className="card-label">Checks Passed</div>
              <div className="card-value pass-value">{passCount}</div>
            </div>
          </div>
          <div className="summary-card">
            <div className="card-icon fail-icon"><XCircle /></div>
            <div className="card-body">
              <div className="card-label">Checks Failed</div>
              <div className="card-value fail-value">{failCount}</div>
            </div>
          </div>
        </div>
      </div>

      <main>
        <div className="tab-nav">
          <button 
            className={`tab-btn ${activeTab === 'ec2' ? 'active' : ''}`}
            onClick={() => setActiveTab('ec2')}
          >
            <Server size={16} /> EC2 Instances 
            {ec2Data.length > 0 && <span className="tab-badge">{ec2Data.length}</span>}
          </button>
          <button 
            className={`tab-btn ${activeTab === 's3' ? 'active' : ''}`}
            onClick={() => setActiveTab('s3')}
          >
            <Database size={16} /> S3 Buckets 
            {s3Data.length > 0 && <span className="tab-badge">{s3Data.length}</span>}
          </button>
          <button 
            className={`tab-btn ${activeTab === 'cis' ? 'active' : ''}`}
            onClick={() => setActiveTab('cis')}
          >
            <ShieldCheck size={16} /> CIS Results 
            {cisData.length > 0 && <span className="tab-badge">{cisData.length}</span>}
          </button>
        </div>

        {/* EC2 Panel */}
        {activeTab === 'ec2' && (
          <div className="tab-panel active">
            <div className="panel-header">
              <h2>Discovered EC2 Instances</h2>
              <button className="btn-refresh" onClick={loadEC2}>
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
            
            {ec2Error && (
              <div className="error-banner">⚠ {ec2Error}</div>
            )}
            
            <div className={`loading-bar ${ec2Loading ? 'active' : ''}`}></div>
            
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Instance ID</th>
                    <th>Type</th>
                    <th>Region</th>
                    <th>State</th>
                    <th>Public IP</th>
                    <th>Private IP</th>
                    <th>Security Groups</th>
                    <th>Name Tag</th>
                  </tr>
                </thead>
                <tbody>
                  {ec2Data.length === 0 && !ec2Loading && (
                    <tr className="empty-row"><td colSpan="8">No EC2 instances found.</td></tr>
                  )}
                  {ec2Loading && ec2Data.length === 0 && (
                     <tr className="empty-row"><td colSpan="8">Loading EC2 instances…</td></tr>
                  )}
                  {ec2Data.map((inst, i) => {
                    const stateClass = {
                      running: "state-running",
                      stopped: "state-stopped",
                      pending: "state-pending",
                    }[inst.state] || "state-other";
                    
                    return (
                      <tr key={inst.instanceId || i}>
                        <td><span className="mono">{inst.instanceId || "—"}</span></td>
                        <td><span className="mono">{inst.instanceType || "—"}</span></td>
                        <td>{inst.region || "—"}</td>
                        <td><span className={`state-badge ${stateClass}`}>{inst.state || "—"}</span></td>
                        <td><span className="mono">{inst.publicIp || "—"}</span></td>
                        <td><span className="mono">{inst.privateIp || "—"}</span></td>
                        <td>
                          <div className="sg-chips">
                            {(inst.securityGroups || []).map((sg, j) => (
                               <span key={j} className="sg-chip">{sg.groupId || sg}</span>
                            ))}
                          </div>
                        </td>
                        <td>{inst.tags?.Name || "—"}</td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* S3 Panel */}
        {activeTab === 's3' && (
          <div className="tab-panel active">
            <div className="panel-header">
              <h2>Discovered S3 Buckets</h2>
              <button className="btn-refresh" onClick={loadS3}>
                <RefreshCw size={14} /> Refresh
              </button>
            </div>
            
            {s3Error && (
              <div className="error-banner">⚠ {s3Error}</div>
            )}
            
            <div className={`loading-bar ${s3Loading ? 'active' : ''}`}></div>
            
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Bucket Name</th>
                    <th>Region</th>
                    <th>Encryption</th>
                    <th>Public Access</th>
                    <th>Block Config</th>
                  </tr>
                </thead>
                <tbody>
                  {s3Data.length === 0 && !s3Loading && (
                    <tr className="empty-row"><td colSpan="5">No S3 buckets found.</td></tr>
                  )}
                  {s3Loading && s3Data.length === 0 && (
                     <tr className="empty-row"><td colSpan="5">Loading S3 buckets…</td></tr>
                  )}
                  {s3Data.map((b, i) => (
                    <tr key={b.bucketName || i}>
                      <td><span className="mono">{b.bucketName || "—"}</span></td>
                      <td>{b.region || "—"}</td>
                      <td>
                        {b.encryptionStatus && b.encryptionStatus !== "NOT_ENABLED"
                          ? <span className="enc-badge enc-enabled">{b.encryptionStatus}</span>
                          : <span className="enc-badge enc-disabled">Not Encrypted</span>}
                      </td>
                      <td>
                        {b.isPublic
                          ? <span className="access-badge access-public">Public</span>
                          : <span className="access-badge access-private">Private</span>}
                      </td>
                      <td>
                        {b.publicAccessBlockEnabled
                           ? <span className="enc-badge enc-enabled">All Blocked</span>
                           : <span className="enc-badge enc-disabled">Partial / None</span>}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* CIS Panel */}
        {activeTab === 'cis' && (
          <div className="tab-panel active">
            <div className="panel-header">
              <h2>CIS Benchmark Results</h2>
              <div className="cis-actions">
                <button className="btn-refresh" onClick={loadCIS}>
                  <RefreshCw size={14} /> Refresh
                </button>
              </div>
            </div>
            
            {cisError && (
              <div className="error-banner">⚠ {cisError}</div>
            )}
            
            <div className={`loading-bar ${cisLoading ? 'active' : ''}`}></div>
            
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Check Name</th>
                    <th>Status</th>
                    <th>Affected Resource</th>
                    <th>Evidence</th>
                    <th>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {cisData.length === 0 && !cisLoading && (
                    <tr className="empty-row"><td colSpan="5">No results yet. Click <strong>Run Scan</strong>.</td></tr>
                  )}
                   {cisLoading && cisData.length === 0 && (
                     <tr className="empty-row"><td colSpan="5">Loading CIS results…</td></tr>
                  )}
                  {cisData.map((r, i) => (
                    <tr key={i}>
                      <td><span className="check-name-cell">{r.checkName || "—"}</span></td>
                      <td>
                        {r.status === "PASS"
                          ? <span className="status-badge status-pass">✓ PASS</span>
                          : <span className="status-badge status-fail">✗ FAIL</span>}
                      </td>
                      <td><span className="mono" style={{fontSize: "0.75rem"}}>{r.affectedResource || r.affected_resource || "—"}</span></td>
                      <td><div className="evidence-cell">{r.evidence || "—"}</div></td>
                      <td><span className="timestamp-cell">{formatTimestamp(r.timestamp)}</span></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </main>

      <footer>
        <div className="container">
          <p>Cloud Posture Scanner • AWS Security Tool</p>
        </div>
      </footer>

      <div id="toast" className={`toast ${toast.show ? 'show' : ''} ${toast.type}`}>
        {toast.msg}
      </div>
    </>
  );
}

export default App;
