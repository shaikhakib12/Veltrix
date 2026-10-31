import React from 'react';
import { 
  LayoutDashboard, 
  Activity, 
  ShieldAlert, 
  AlertTriangle, 
  Globe, 
  Zap, 
  Terminal, 
  Lock, 
  Settings 
} from 'lucide-react';

export type NavTab = 
  | 'overview' 
  | 'events' 
  | 'detection' 
  | 'incidents' 
  | 'threat-intel' 
  | 'response' 
  | 'simulation' 
  | 'audit' 
  | 'settings';

interface SidebarProps {
  activeTab: NavTab;
  onSelectTab: (tab: NavTab) => void;
  openIncidentsCount: number;
  pendingApprovalsCount: number;
}

export const Sidebar: React.FC<SidebarProps> = ({
  activeTab,
  onSelectTab,
  openIncidentsCount,
  pendingApprovalsCount,
}) => {
  const navItems = [
    { id: 'overview' as NavTab, label: 'SOC Overview', icon: LayoutDashboard },
    { id: 'events' as NavTab, label: 'Live Events', icon: Activity },
    { id: 'detection' as NavTab, label: 'Threat Detection', icon: ShieldAlert },
    { 
      id: 'incidents' as NavTab, 
      label: 'Incidents', 
      icon: AlertTriangle, 
      badge: openIncidentsCount > 0 ? openIncidentsCount : undefined,
      badgeColor: 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
    },
    { id: 'threat-intel' as NavTab, label: 'Threat Intel', icon: Globe },
    { 
      id: 'response' as NavTab, 
      label: 'Response Center', 
      icon: Zap, 
      badge: pendingApprovalsCount > 0 ? pendingApprovalsCount : undefined,
      badgeColor: 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse'
    },
    { id: 'simulation' as NavTab, label: 'Simulation Lab', icon: Terminal, highlight: true },
    { id: 'audit' as NavTab, label: 'Audit Ledger', icon: Lock },
    { id: 'settings' as NavTab, label: 'Settings', icon: Settings },
  ];

  return (
    <aside className="w-64 border-r border-slate-800/80 bg-navy-950 flex flex-col justify-between p-4 shrink-0">
      <div>
        <div className="px-3 mb-3 text-[10px] font-mono tracking-wider uppercase text-slate-500 font-semibold">
          Security Operations
        </div>
        <nav className="space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectTab(item.id)}
                className={`w-full flex items-center justify-between px-3 py-2.5 rounded-lg text-xs font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-accent border border-cyan-500/30 shadow-glow-cyan'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-900/60'
                } ${item.highlight && !isActive ? 'border border-cyan-500/20 text-cyan-300/90' : ''}`}
              >
                <div className="flex items-center space-x-3">
                  <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-accent' : 'text-slate-400'}`} />
                  <span>{item.label}</span>
                </div>
                {item.badge !== undefined && (
                  <span className={`text-[10px] font-mono px-2 py-0.5 rounded-full font-bold ${item.badgeColor}`}>
                    {item.badge}
                  </span>
                )}
              </button>
            );
          })}
        </nav>
      </div>

      {/* Footer System Telemetry */}
      <div className="p-3 rounded-lg bg-navy-900 border border-slate-800/60 space-y-2 text-[11px]">
        <div className="flex items-center justify-between text-slate-400">
          <span className="font-mono text-[10px] uppercase">Engine Status</span>
          <span className="text-emerald-400 font-mono font-medium flex items-center">
            <span className="w-1.5 h-1.5 rounded-full bg-emerald-400 mr-1.5"></span>
            ACTIVE
          </span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span className="font-mono text-[10px] uppercase">Sigma Rules</span>
          <span className="text-slate-200 font-mono">10 / 10 Loaded</span>
        </div>
        <div className="flex items-center justify-between text-slate-400">
          <span className="font-mono text-[10px] uppercase">Audit Ledger</span>
          <span className="text-cyan-400 font-mono">SHA-256 Chained</span>
        </div>
      </div>
    </aside>
  );
};
