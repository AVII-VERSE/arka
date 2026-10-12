import React, { useState, useEffect } from 'react';
import { ShieldCheck, CheckCircle2, XCircle, RefreshCw } from 'lucide-react';
import { api } from '../api/client';
import { SCAReport } from '../types';

export const SCAView: React.FC = () => {
  const [reports, setReports] = useState<SCAReport[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedReport, setSelectedReport] = useState<SCAReport | null>(null);

  const loadData = async () => {
    setLoading(true);
    try {
      const data = await api.getSCA();
      if (data && data.length > 0) {
        setReports(data);
        setSelectedReport(data[0]);
      } else {
        // Fallback default CIS benchmarks if none yet in DB
        const defaultReports: SCAReport[] = [
          {
            policy_id: 'cis-ubuntu-22-04',
            policy_name: 'CIS Ubuntu Linux 22.04 LTS Benchmark v1.1',
            agent_id: 'dc-primary-01.corp.local',
            compliance_score: 87.5,
            total_checks: 40,
            passed_checks: 35,
            failed_checks: 5,
            checks: [
              { check_id: 'CIS-1.1.1', title: 'Ensure cramfs is disabled', status: 'PASSED', remediation: 'Add "install cramfs /bin/true" to modprobe.d' },
              { check_id: 'CIS-1.1.2', title: 'Ensure separate /tmp partition', status: 'PASSED', remediation: 'Mount /tmp with nodev, nosuid, noexec' },
              { check_id: 'CIS-5.2.1', title: 'Ensure SSH PermitRootLogin is disabled', status: 'FAILED', remediation: 'Set PermitRootLogin no in /etc/ssh/sshd_config' },
              { check_id: 'CIS-5.2.2', title: 'Ensure SSH MaxAuthTries is set to 4', status: 'PASSED', remediation: 'Set MaxAuthTries 4 in sshd_config' },
              { check_id: 'CIS-5.3.1', title: 'Ensure password minimum length is 14', status: 'FAILED', remediation: 'Configure pam_pwquality minlen=14' },
            ],
          },
          {
            policy_id: 'cis-win-server-2022',
            policy_name: 'CIS Microsoft Windows Server 2022 Benchmark v2.0',
            agent_id: 'win-dc-01.corp.local',
            compliance_score: 92.0,
            total_checks: 50,
            passed_checks: 46,
            failed_checks: 4,
            checks: [
              { check_id: 'CIS-2.3.1', title: 'Accounts: Rename administrator account', status: 'PASSED', remediation: 'Rename via GPO' },
              { check_id: 'CIS-2.3.2', title: 'Accounts: Rename guest account', status: 'PASSED', remediation: 'Rename via GPO' },
              { check_id: 'CIS-18.9.1', title: 'Ensure Windows Defender Credential Guard is enabled', status: 'FAILED', remediation: 'Enable LSA protection in Registry' },
            ],
          },
        ];
        setReports(defaultReports);
        setSelectedReport(defaultReports[0]);
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

  return (
    <div className="p-6 space-y-6 font-sans">
      {/* Header */}
      <div className="glass-card rounded-2xl p-5 flex items-center justify-between">
        <div>
          <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-emerald-400" /> Security Configuration Assessment (SCA)
          </h3>
          <p className="text-xs text-slate-400 mt-0.5">
            CIS Benchmarks & OS Hardening Compliance Auditor across registered endpoints.
          </p>
        </div>
        <button
          onClick={loadData}
          className="flex items-center gap-2 px-3 py-1.5 bg-slate-900 border border-slate-800 hover:border-emerald-500/50 text-slate-200 rounded-xl text-xs font-mono transition-all"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${loading ? 'animate-spin text-emerald-400' : 'text-slate-400'}`} />
          <span>Scan Policies</span>
        </button>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 font-mono">
        {/* Policies List */}
        <div className="space-y-3">
          <h4 className="text-xs font-bold text-slate-400 uppercase tracking-wider">
            Audited Benchmarks ({reports.length})
          </h4>
          {reports.map((r, i) => (
            <div
              key={r.policy_id || i}
              onClick={() => setSelectedReport(r)}
              className={`p-4 rounded-xl cursor-pointer transition-all border ${
                selectedReport?.policy_id === r.policy_id
                  ? 'bg-slate-900/90 border-emerald-500/50 shadow-lg shadow-emerald-500/10'
                  : 'bg-slate-900/40 border-slate-800 hover:border-slate-700'
              }`}
            >
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs font-bold text-slate-200">{r.policy_name}</span>
                <span className="text-xs font-extrabold text-emerald-400">{r.compliance_score}%</span>
              </div>
              <p className="text-[10px] text-slate-400 truncate">Agent: {r.agent_id}</p>
              <div className="flex items-center gap-3 mt-3 text-[10px]">
                <span className="text-emerald-400 font-bold flex items-center gap-1">
                  <CheckCircle2 className="w-3 h-3" /> {r.passed_checks} Passed
                </span>
                <span className="text-rose-400 font-bold flex items-center gap-1">
                  <XCircle className="w-3 h-3" /> {r.failed_checks} Failed
                </span>
              </div>
            </div>
          ))}
        </div>

        {/* Selected Policy Breakdown */}
        <div className="lg:col-span-2 glass-card rounded-2xl p-5 space-y-4">
          {selectedReport ? (
            <>
              <div className="flex items-center justify-between border-b border-slate-800 pb-3">
                <div>
                  <h4 className="text-sm font-bold text-slate-100">{selectedReport.policy_name}</h4>
                  <p className="text-[11px] text-slate-400">Target Endpoint: {selectedReport.agent_id}</p>
                </div>
                <div className="text-right">
                  <span className="text-2xl font-extrabold text-emerald-400">
                    {selectedReport.compliance_score}%
                  </span>
                  <p className="text-[9px] text-slate-500 uppercase">CIS COMPLIANCE</p>
                </div>
              </div>

              <div className="space-y-2">
                <h5 className="text-xs font-bold text-slate-300 uppercase">Audit Check Rules</h5>
                <div className="space-y-2 max-h-96 overflow-y-auto pr-1">
                  {(selectedReport.checks || []).map((chk) => (
                    <div
                      key={chk.check_id}
                      className="p-3 rounded-xl bg-slate-900/80 border border-slate-800 space-y-1.5"
                    >
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-bold text-cyan-400">{chk.check_id} - {chk.title}</span>
                        <span
                          className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                            chk.status === 'PASSED'
                              ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                              : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                          }`}
                        >
                          {chk.status}
                        </span>
                      </div>
                      {chk.remediation && (
                        <p className="text-[11px] text-slate-400 font-sans">
                          <strong className="text-slate-300 font-mono">Remediation:</strong> {chk.remediation}
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </>
          ) : (
            <div className="p-8 text-center text-slate-500 text-xs">
              Select an SCA policy to view detailed compliance audit results.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
