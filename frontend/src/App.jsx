import { useEffect, useState } from "react";
import "./App.css";

const API_BASE = "http://127.0.0.1:8000";
const REFRESH_INTERVAL = 2000;

function App() {
  const [liveTraffic, setLiveTraffic] = useState(null);
  const [activeFlows, setActiveFlows] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [captureStatus, setCaptureStatus] = useState({ running: false });

  useEffect(() => {
    const fetchAll = async () => {
      try {
        const res = await fetch(`${API_BASE}/capture-status`);
        setCaptureStatus(await res.json());
      } catch {
        setCaptureStatus({ running: false });
      }

      try {
        const res = await fetch(`${API_BASE}/live-traffic`);
        setLiveTraffic(await res.json());
      } catch {
        setLiveTraffic(null);
      }

      try {
        const res = await fetch(`${API_BASE}/active-flows`);
        setActiveFlows(await res.json());
      } catch {
        setActiveFlows([]);
      }

      try {
        const res = await fetch(`${API_BASE}/alerts?limit=50`);
        setAlerts(await res.json());
      } catch {
        setAlerts([]);
      }
    };

    fetchAll();
    const interval = setInterval(fetchAll, REFRESH_INTERVAL);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="app-root">
      <div className="dashboard">

        {/* ================= HEADER ================= */}
        <div className="header">
          <h1>NIDS Admin Dashboard</h1>
          <div className="capture-status">
            Capture Status:&nbsp;
            {captureStatus.running ? (
              <span className="status running">🟢 Running</span>
            ) : (
              <span className="status stopped">🔴 Stopped</span>
            )}
          </div>
        </div>

        {/* ================= LIVE TRAFFIC ================= */}
        <div className="section">
          <h2>Live Traffic (Last 2s)</h2>
          <table className="table">
            <thead>
              <tr>
                <th>Total Packets</th>
                <th>TCP Packets</th>
                <th>UDP Packets</th>
              </tr>
            </thead>
            <tbody>
              {liveTraffic ? (
                <tr>
                  <td>{liveTraffic.total_packets}</td>
                  <td>{liveTraffic.tcp_packets}</td>
                  <td>{liveTraffic.udp_packets}</td>
                </tr>
              ) : (
                <tr>
                  <td colSpan="3">No data</td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* ================= ACTIVE FLOWS ================= */}
        <div className="section">
          <h2>Active Flows (Live)</h2>
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Duration (s)</th>
                  <th>Packets</th>
                  <th>Last Seen (s)</th>
                </tr>
              </thead>
              <tbody>
                {activeFlows.length === 0 ? (
                  <tr>
                    <td colSpan="6">No active flows</td>
                  </tr>
                ) : (
                  activeFlows.map((f, i) => (
                    <tr key={i}>
                      <td>{f.src_ip}:{f.src_port}</td>
                      <td>{f.dst_ip}:{f.dst_port}</td>
                      <td>{f.protocol}</td>
                      <td>{f.duration}</td>
                      <td>{f.packet_count}</td>
                      <td>{f.last_seen_seconds}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* ================= ALERTS ================= */}
        <div className="section">
          <h2>Alerts (Completed Flows)</h2>
          <div className="table-container">
            <table className="table">
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Protocol</th>
                  <th>Probability</th>
                  <th>Severity</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length === 0 ? (
                  <tr>
                    <td colSpan="6">No alerts</td>
                  </tr>
                ) : (
                  alerts.map(a => (
                    <tr key={a.id}>
                      <td>{a.timestamp}</td>
                      <td>{a.src_ip}:{a.src_port}</td>
                      <td>{a.dst_ip}:{a.dst_port}</td>
                      <td>{a.protocol}</td>
                      <td className="mono">{a.attack_probability.toFixed(4)}</td>
                      <td className={`sev ${a.severity.toLowerCase()}`}>
                        {a.severity}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}

export default App;
