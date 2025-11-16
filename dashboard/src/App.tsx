import { useState, useEffect } from 'react'
import axios from 'axios'
import './App.css'

interface Scan {
  id: number
  target: string
  scan_type: string
  status: string
  started_at: string
  completed_at: string | null
}

interface Finding {
  id: number
  title: string
  description: string
  severity: string
  category: string
  cve_id: string | null
  cvss_score: number | null
  recommendation: string | null
}

const API_BASE = 'http://localhost:8000'

function App() {
  const [scans, setScans] = useState<Scan[]>([])
  const [selectedScan, setSelectedScan] = useState<number | null>(null)
  const [findings, setFindings] = useState<Finding[]>([])
  const [loading, setLoading] = useState(false)
  const [target, setTarget] = useState('localhost')
  const [scanType, setScanType] = useState('full')

  useEffect(() => {
    loadScans()
  }, [])

  useEffect(() => {
    if (selectedScan) {
      loadFindings(selectedScan)
    }
  }, [selectedScan])

  const loadScans = async () => {
    try {
      const response = await axios.get(`${API_BASE}/scans?limit=20`)
      setScans(response.data)
    } catch (error) {
      console.error('Failed to load scans:', error)
    }
  }

  const loadFindings = async (scanId: number) => {
    try {
      const response = await axios.get(`${API_BASE}/scans/${scanId}/findings`)
      setFindings(response.data)
    } catch (error) {
      console.error('Failed to load findings:', error)
    }
  }

  const startScan = async () => {
    setLoading(true)
    try {
      const response = await axios.post(`${API_BASE}/scans`, {
        target,
        scan_type: scanType,
        compliance_frameworks: ['cis'],
      })
      await loadScans()
      setSelectedScan(response.data.id)
    } catch (error) {
      console.error('Failed to start scan:', error)
      alert('Failed to start scan. Make sure the API server is running.')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return '#dc3545'
      case 'high':
        return '#fd7e14'
      case 'medium':
        return '#ffc107'
      case 'low':
        return '#0dcaf0'
      default:
        return '#6c757d'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'completed':
        return '#28a745'
      case 'running':
        return '#007bff'
      case 'failed':
        return '#dc3545'
      default:
        return '#6c757d'
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>Security Automation Platform</h1>
        <p>Comprehensive security scanning and compliance checking</p>
      </header>

      <div className="app-container">
        <div className="scan-controls">
          <h2>Start New Scan</h2>
          <div className="form-group">
            <label>Target:</label>
            <input
              type="text"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder="localhost"
            />
          </div>
          <div className="form-group">
            <label>Scan Type:</label>
            <select value={scanType} onChange={(e) => setScanType(e.target.value)}>
              <option value="full">Full Scan</option>
              <option value="compliance">Compliance Only</option>
              <option value="vulnerability">Vulnerability Only</option>
              <option value="config">Configuration Only</option>
            </select>
          </div>
          <button onClick={startScan} disabled={loading}>
            {loading ? 'Starting...' : 'Start Scan'}
          </button>
        </div>

        <div className="scans-section">
          <h2>Recent Scans</h2>
          <div className="scans-list">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className={`scan-card ${selectedScan === scan.id ? 'selected' : ''}`}
                onClick={() => setSelectedScan(scan.id)}
              >
                <div className="scan-header">
                  <span className="scan-id">#{scan.id}</span>
                  <span
                    className="scan-status"
                    style={{ color: getStatusColor(scan.status) }}
                  >
                    {scan.status}
                  </span>
                </div>
                <div className="scan-info">
                  <p><strong>Target:</strong> {scan.target}</p>
                  <p><strong>Type:</strong> {scan.scan_type}</p>
                  <p><strong>Started:</strong> {new Date(scan.started_at).toLocaleString()}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {selectedScan && (
          <div className="findings-section">
            <h2>Findings for Scan #{selectedScan}</h2>
            {findings.length === 0 ? (
              <p>No findings available for this scan.</p>
            ) : (
              <div className="findings-list">
                {findings.map((finding) => (
                  <div key={finding.id} className="finding-card">
                    <div className="finding-header">
                      <span
                        className="severity-badge"
                        style={{ backgroundColor: getSeverityColor(finding.severity) }}
                      >
                        {finding.severity.toUpperCase()}
                      </span>
                      <span className="category-badge">{finding.category}</span>
                      {finding.cve_id && (
                        <span className="cve-badge">{finding.cve_id}</span>
                      )}
                    </div>
                    <h3>{finding.title}</h3>
                    <p>{finding.description}</p>
                    {finding.cvss_score && (
                      <p><strong>CVSS Score:</strong> {finding.cvss_score}</p>
                    )}
                    {finding.recommendation && (
                      <div className="recommendation">
                        <strong>Recommendation:</strong> {finding.recommendation}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

export default App

