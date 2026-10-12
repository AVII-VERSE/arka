import React from 'react';
import { Bell, X, CheckCircle, ArrowRight } from 'lucide-react';
import { Alert } from '../types';

interface NotificationDrawerProps {
  isOpen: boolean;
  onClose: () => void;
  alerts: Alert[];
  onInspectAlert?: (alert: Alert) => void;
  onAcknowledgeAlert?: (alertId: string) => void;
}

export const NotificationDrawer: React.FC<NotificationDrawerProps> = ({
  isOpen,
  onClose,
  alerts,
  onInspectAlert,
  onAcknowledgeAlert,
}) => {
  if (!isOpen) return null;

  const criticalAlerts = alerts.filter((a) => a.severity === 'CRITICAL');
  const highAlerts = alerts.filter((a) => a.severity === 'HIGH');

  return (
    <div className="fixed inset-0 z-50 overflow-hidden bg-slate-950/60 backdrop-blur-sm">
      <div className="absolute inset-y-0 right-0 max-w-full flex pl-10">
        <div className="w-screen max-w-md bg-slate-950/95 border-l border-slate-800 shadow-2xl flex flex-col font-sans">
          {/* Header */}
          <div className="p-4 border-b border-slate-800 flex items-center justify-between">
            <div className="flex items-center gap-2.5">
              <div className="p-2 rounded-xl bg-rose-500/10 border border-rose-500/20 text-rose-400">
                <Bell className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-sm font-mono font-bold text-slate-100 uppercase tracking-wider flex items-center gap-2">
                  SOC Notification Feed
                </h3>
                <p className="text-[10px] font-mono text-slate-400">
                  {criticalAlerts.length} Critical · {highAlerts.length} High Alerts
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-1.5 rounded-xl bg-slate-900 border border-slate-800 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          </div>

          {/* Alert List */}
          <div className="flex-1 overflow-y-auto p-4 space-y-3">
            {alerts.slice(0, 15).map((alert) => (
              <div
                key={alert.id}
                className="p-3 rounded-xl bg-slate-900/80 border border-slate-800/80 hover:border-slate-700 transition-all font-mono space-y-2"
              >
                <div className="flex items-center justify-between">
                  <span
                    className={`px-2 py-0.5 rounded-full text-[9px] font-bold ${
                      alert.severity === 'CRITICAL'
                        ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
                        : alert.severity === 'HIGH'
                        ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30'
                        : 'bg-cyan-500/20 text-cyan-400 border border-cyan-500/30'
                    }`}
                  >
                    {alert.severity}
                  </span>
                  <span className="text-[10px] text-slate-500">
                    {new Date(alert.created_at).toLocaleTimeString()}
                  </span>
                </div>

                <div>
                  <h4 className="text-xs font-bold text-slate-200">{alert.rule_code}</h4>
                  <p className="text-[11px] text-slate-400 font-sans line-clamp-2 mt-0.5">
                    {alert.reason}
                  </p>
                </div>

                <div className="flex items-center justify-between pt-1 border-t border-slate-800/60 text-[10px] text-slate-400">
                  <span className="text-cyan-400 font-bold">{alert.host}</span>
                  <div className="flex items-center gap-2">
                    {onAcknowledgeAlert && alert.status !== 'ACKNOWLEDGED' && (
                      <button
                        onClick={() => onAcknowledgeAlert(alert.id)}
                        className="text-emerald-400 hover:underline flex items-center gap-1"
                      >
                        <CheckCircle className="w-3 h-3" /> Ack
                      </button>
                    )}
                    {onInspectAlert && (
                      <button
                        onClick={() => {
                          onInspectAlert(alert);
                          onClose();
                        }}
                        className="text-cyan-400 hover:underline flex items-center gap-1 font-bold"
                      >
                        Triage <ArrowRight className="w-3 h-3" />
                      </button>
                    )}
                  </div>
                </div>
              </div>
            ))}

            {alerts.length === 0 && (
              <div className="p-8 text-center text-slate-500 text-xs font-mono">
                No active security alerts pending notification.
              </div>
            )}
          </div>

          {/* Footer */}
          <div className="p-3 border-t border-slate-800 bg-slate-950 text-center">
            <span className="text-[11px] font-mono text-slate-500">
              Live alert dispatch via Kafka Stream & Webhook Pipeline
            </span>
          </div>
        </div>
      </div>
    </div>
  );
};
