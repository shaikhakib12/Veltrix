import React, { useState } from 'react';
import { DetectionRule } from '../types/index.js';
import { ShieldCheck, ShieldAlert, Sliders, ExternalLink, Zap } from 'lucide-react';

interface ThreatDetectionProps {
  rules: DetectionRule[];
  onToggleRule: (ruleId: string, currentEnabled: boolean) => void;
  onUpdateThreshold: (ruleId: string, newThreshold: number) => void;
}

export const ThreatDetection: React.FC<ThreatDetectionProps> = ({
  rules,
  onToggleRule,
  onUpdateThreshold,
}) => {
  const [editingRuleId, setEditingRuleId] = useState<string | null>(null);
  const [tempThreshold, setTempThreshold] = useState<number>(1);

  const handleEditThreshold = (rule: DetectionRule) => {
    setEditingRuleId(rule.ruleId);
    setTempThreshold(rule.threshold);
  };

  const handleSaveThreshold = (ruleId: string) => {
    onUpdateThreshold(ruleId, tempThreshold);
    setEditingRuleId(null);
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h2 className="text-base font-semibold text-white font-mono flex items-center space-x-2">
          <span>SIGMA-INSPIRED THREAT DETECTION RULES CATALOG</span>
          <span className="text-xs px-2 py-0.5 rounded bg-cyan-500/10 text-cyan-accent border border-cyan-500/30">
            {rules.filter(r => r.enabled).length} / {rules.length} Active
          </span>
        </h2>
        <p className="text-xs text-slate-400">
          Declarative detection rules mapped to MITRE ATT&CK techniques with real-time sliding window evaluation and dynamic threshold tuning.
        </p>
      </div>

      {/* Rules Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {rules.map((rule) => {
          const isCritical = rule.severity === 'CRITICAL';
          const isHigh = rule.severity === 'HIGH';

          return (
            <div
              key={rule.ruleId}
              className={`p-5 rounded-xl bg-navy-900 border transition ${
                rule.enabled 
                  ? isCritical 
                    ? 'border-rose-500/30' 
                    : isHigh 
                      ? 'border-amber-500/30' 
                      : 'border-slate-800' 
                  : 'border-slate-800/40 opacity-60'
              }`}
            >
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="flex items-center space-x-2.5">
                  <div className={`p-2 rounded-lg ${
                    rule.enabled 
                      ? isCritical 
                        ? 'bg-rose-500/10 text-rose-400' 
                        : 'bg-cyan-500/10 text-cyan-accent' 
                      : 'bg-slate-800 text-slate-500'
                  }`}>
                    {rule.enabled ? <ShieldCheck className="w-5 h-5" /> : <ShieldAlert className="w-5 h-5" />}
                  </div>
                  <div>
                    <div className="flex items-center space-x-2">
                      <span className="text-xs font-mono font-bold text-slate-400">{rule.ruleId}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.2 rounded font-bold ${
                        isCritical 
                          ? 'bg-rose-500/20 text-rose-300' 
                          : isHigh 
                            ? 'bg-amber-500/20 text-amber-300' 
                            : 'bg-sky-500/20 text-sky-300'
                      }`}>
                        {rule.severity}
                      </span>
                    </div>
                    <h3 className="text-sm font-semibold text-white mt-0.5">{rule.name}</h3>
                  </div>
                </div>

                {/* Enable/Disable Toggle */}
                <button
                  onClick={() => onToggleRule(rule.ruleId, rule.enabled)}
                  className={`text-[11px] font-mono px-2.5 py-1 rounded-full font-semibold transition ${
                    rule.enabled
                      ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40'
                      : 'bg-slate-800 text-slate-500 border border-slate-700'
                  }`}
                >
                  {rule.enabled ? 'ACTIVE' : 'MUTED'}
                </button>
              </div>

              <p className="text-xs text-slate-400 mb-4 leading-relaxed">
                {rule.description}
              </p>

              {/* MITRE ATT&CK Mapping & Response */}
              <div className="space-y-2 pt-3 border-t border-slate-800/80 text-xs">
                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-mono text-[11px]">MITRE Tactic:</span>
                  <a
                    href={rule.mitreAttack.url}
                    target="_blank"
                    rel="noreferrer"
                    className="flex items-center space-x-1 text-cyan-400 hover:text-cyan-300 font-mono text-[11px]"
                  >
                    <span>{rule.mitreAttack.techniqueId} - {rule.mitreAttack.techniqueName}</span>
                    <ExternalLink className="w-3 h-3" />
                  </a>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-mono text-[11px]">Sliding Window:</span>
                  <span className="text-slate-300 font-mono text-[11px]">{rule.timeWindowSeconds} seconds</span>
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-mono text-[11px]">Threshold:</span>
                  {editingRuleId === rule.ruleId ? (
                    <div className="flex items-center space-x-1">
                      <input
                        type="number"
                        min="1"
                        max="100"
                        value={tempThreshold}
                        onChange={(e) => setTempThreshold(parseInt(e.target.value, 10) || 1)}
                        className="w-14 py-0.5 px-1.5 rounded bg-navy-950 border border-cyan-500/50 text-white font-mono text-xs text-center"
                      />
                      <button
                        onClick={() => handleSaveThreshold(rule.ruleId)}
                        className="text-[10px] px-2 py-0.5 rounded bg-cyan-500 text-slate-950 font-bold"
                      >
                        Save
                      </button>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-200 font-mono text-[11px] font-bold">
                        $\ge {rule.threshold}$ events
                      </span>
                      <button
                        onClick={() => handleEditThreshold(rule)}
                        className="text-slate-500 hover:text-cyan-accent p-1"
                        title="Tune Threshold"
                      >
                        <Sliders className="w-3 h-3" />
                      </button>
                    </div>
                  )}
                </div>

                <div className="flex items-center justify-between">
                  <span className="text-slate-500 font-mono text-[11px]">Recommended Response:</span>
                  <span className="flex items-center space-x-1 px-2 py-0.5 rounded bg-slate-800 text-slate-200 font-mono text-[10px] font-semibold">
                    <Zap className="w-3 h-3 text-cyan-accent" />
                    <span>{rule.recommendedAction}</span>
                  </span>
                </div>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
