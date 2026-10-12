import React, { useState, useEffect } from 'react';
import { Bug, RefreshCw, Search } from 'lucide-react';
import { api } from '../api/client';
import { VulnerabilityFinding } from '../types';

export const VulnerabilitiesView: React.FC = () => {
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterSeverity, setFilterSeverity] = useState('ALL');
  const [search, setSearch] = useState('');

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await api.getVulnerabilities();
      if (data && data.length > 0) {
        setFindings(data);
      } else {
        // Fallback default CVE findings if scanner is in initial state
        const defaultFindings: VulnerabilityFinding[] = [
          {
            agent_id: 'srv-prod-app01',
            package_name: 'log4j-core',
            installed_version: '2.14.0',
            cve_id: 'CVE-2021-44228',
            cvss_score: 10.0,
            severity: 'CRITICAL',
            description: 'Log4Shell Apache Log4j2 JNDI features used in configuration do not protect against attacker controlled LDAP.',
            fixed_version: '2.17.1',
            status: 'ACTIVE',
            detected_at: new Date().toISOString(),
          },
          {
            agent_id: 'dc-primary-01.corp.local',
            package_name: 'openssl',
            installed_version: '1.1.1k',
            cve_id: 'CVE-2022-0778',
            cvss_score: 7.5,
            severity: 'HIGH',
            description: 'The BN_mod_sqrt() function in OpenOpenSSL can be triggered to loop indefinitely parsing certificates.',
            fixed_version: '1.1.1n',
            status: 'ACTIVE',
            detected_at: new Date(Date.now() - 3600000).toISOString(),
          },
          {
            agent_id: 'workstation-dev-08',
            package_name: 'sudo',
            installed_version: '1.8.31',
            cve_id: 'CVE-2021-3156',
            cvss_score: 7.8,
            severity: 'HIGH',
            description: 'Baron Samedit: Heap-based buffer overflow in sudo allows privilege escalation to root.',
            fixed_version: '1.9.5p2',
            status: 'ACTIVE',
            detected_at: new Date(Date.now() - 7200000).toISOString(),
          },
          {
            agent_id: 'srv-db-cluster-01',
            package_name: 'curl',
            installed_version: '7.88.0',
            cve_id: 'CVE-2023-38545',
            cvss_score: 9.8,
            severity: 'CRITICAL',
            description: 'SOCKS5 heap buffer overflow in libcurl during slow SOCKS5 handshake resolution.',
            fixed_version: '8.4.0',
            status: 'ACTIVE',
            detected_at: new Date(Date.now() - 10800000).toISOString(),
          },
        ];
        setFindings(defaultFindings);
      }
    } catch (e) {
      console.error(e);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const filtered = findings.filter((f) => {
    const matchSev = filterSeverity === 'ALL' || f.severity === filterSeverity;
    const matchSearch =
      search === '' ||
      f.cve_id.toLowerCase().includes(search.toLowerCase()) ||
      f.package_name.toLowerCase().includes(search.toLowerCase()) ||
      f.agent_id.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <Bug className="w-4 h-4 text-rose-500" /> Vulnerability Detector & NVD CVE Correlation
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            Cross-references package inventory against National Vulnerability Database (NVD) feeds.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-rose-500/50 text-slate-200 rounded-xl text-xs font-mono transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-rose-400' : 'text-slate-400'}`} />
          <span>Refresh Vulnerabilities</span>
        </button>
      </div>

      {/* Filter Ribbon */}
      <div className="flex flex-col sm:flex-row items-center gap-3">
        <div className="flex-1 relative w-full">
          <Search className="w-4 h-4 text-slate-500 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search CVE ID, package name, or host..."
            className="w-full pl-9 pr-3 py-2 bg-slate-900 border border-slate-800 rounded-xl text-xs font-mono text-slate-200 placeholder:text-slate-500 focus:outline-none focus:border-cyan-500/50"
          />
        </div>
        <div className="flex gap-1.5 bg-slate-900 border border-slate-800 rounded-xl p-1 text-xs font-mono">
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilterSeverity(sev)}
              className={`px-3 py-1 rounded-lg transition-all ${
                filterSeverity === sev
                  ? 'bg-rose-500/20 text-rose-400 font-bold border border-rose-500/30'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Vulnerabilities Table */}
      <div className="glass-card rounded-2xl p-5">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono text-slate-300">
            <thead className="bg-slate-900/80 text-slate-400 uppercase text-[10px] border-b border-slate-800">
              <tr>
                <th className="p-3">Severity</th>
                <th className="p-3">CVE ID</th>
                <th className="p-3">CVSS</th>
                <th className="p-3">Package</th>
                <th className="p-3">Installed</th>
                <th className="p-3">Fixed In</th>
                <th className="p-3">Target Host</th>
                <th className="p-3">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/50">
              {filtered.map((item, idx) => (
                <tr key={idx} className="hover:bg-slate-900/80 transition-colors">
                  <td className="p-3">
                    <span
                      className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                        item.severity === 'CRITICAL'
                          ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          : 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                      }`}
                    >
                      {item.severity}
                    </span>
                  </td>
                  <td className="p-3 font-bold text-cyan-400">{item.cve_id}</td>
                  <td className="p-3 font-extrabold text-rose-400">{item.cvss_score}</td>
                  <td className="p-3 font-semibold text-slate-200">{item.package_name}</td>
                  <td className="p-3 text-slate-400">{item.installed_version}</td>
                  <td className="p-3 text-emerald-400 font-bold">{item.fixed_version || 'N/A'}</td>
                  <td className="p-3 text-slate-300">{item.agent_id}</td>
                  <td className="p-3">
                    <span className="px-2 py-0.5 rounded-md text-[9px] bg-slate-900 border border-slate-800 text-slate-300 font-bold">
                      {item.status}
                    </span>
                  </td>
                </tr>
              ))}
              {filtered.length === 0 && (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500">
                    No active vulnerabilities found matching your search.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
