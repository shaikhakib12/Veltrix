import React from 'react';
import { 
  ShieldAlert, 
  Activity, 
  AlertTriangle, 
  Flame, 
  ShieldBan, 
  Clock, 
  ArrowUpRight,
  TrendingUp,
  Terminal
} from 'lucide-react';
import { 
  AreaChart, 
  Area, 
  XAxis, 
  YAxis, 
  Tooltip, 
  ResponsiveContainer, 
  PieChart, 
  Pie, 
  Cell, 
  BarChart, 
  Bar 
} from 'recharts';

interface DashboardOverviewProps {
  analytics: {
    totalEvents: number;
    threatsDetected: number;
    openIncidents: number;
    criticalIncidents: number;
    activeBlockedIps: number;
    meanTimeToDetectMinutes: number;
    meanTimeToRespondMinutes: number;
    severityDistribution: Record<string, number>;
    mitreDistribution: Record<string, number>;
    authMetrics: { failed: number; success: number };
  } | null;
  onNavigateToSimulation: () => void;
  onNavigateToIncidents: () => void;
}

export const DashboardOverview: React.FC<DashboardOverviewProps> = ({
  analytics,
  onNavigateToSimulation,
  onNavigateToIncidents,
}) => {
  // Mock velocity telemetry for realistic SOC time-series chart
  const velocityData = [
    { time: '10:00', events: 1420, threats: 3 },
    { time: '12:00', events: 1980, threats: 5 },
    { time: '14:00', events: 2450, threats: 12 },
    { time: '16:00', events: 3100, threats: 18 },
    { time: '18:00', events: 2850, threats: 8 },
    { time: '20:00', events: 3900, threats: 24 },
    { time: '22:00', events: analytics?.totalEvents || 4200, threats: analytics?.threatsDetected || 15 },
  ];

  // Severity Donut Colors
  const SEVERITY_COLORS: Record<string, string> = {
    CRITICAL: '#F43F5E', // Rose
    HIGH: '#FB923C',     // Orange
    MEDIUM: '#FBBF24',   // Amber
    LOW: '#38BDF8',      // Sky
  };

  const severityData = [
    { name: 'Critical', value: analytics?.severityDistribution?.CRITICAL || 0, color: SEVERITY_COLORS.CRITICAL },
    { name: 'High', value: analytics?.severityDistribution?.HIGH || 0, color: SEVERITY_COLORS.HIGH },
    { name: 'Medium', value: analytics?.severityDistribution?.MEDIUM || 0, color: SEVERITY_COLORS.MEDIUM },
    { name: 'Low', value: analytics?.severityDistribution?.LOW || 0, color: SEVERITY_COLORS.LOW },
  ].filter(d => d.value > 0);

  // If no severity data yet, show default healthy baseline
  const displaySeverityData = severityData.length > 0 ? severityData : [
    { name: 'Normal / Clean', value: 100, color: '#10B981' }
  ];

  // MITRE Breakdown
  const mitreData = Object.entries(analytics?.mitreDistribution || {}).map(([tactic, count]) => ({
    tactic,
    count,
  }));

  const defaultMitre = mitreData.length > 0 ? mitreData : [
    { tactic: 'Credential Access', count: 4 },
    { tactic: 'Privilege Escalation', count: 2 },
    { tactic: 'Exfiltration', count: 1 },
    { tactic: 'Initial Access', count: 3 },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner Alert / Action Callout */}
      <div className="p-4 rounded-xl bg-gradient-to-r from-navy-900 via-navy-850 to-slate-900 border border-cyan-500/30 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4 shadow-glow-cyan">
        <div className="flex items-center space-x-3">
          <div className="p-2.5 rounded-lg bg-cyan-500/10 text-cyan-accent border border-cyan-400/30">
            <ShieldAlert className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white">Autonomous Threat Monitoring Active</h2>
            <p className="text-xs text-slate-400">
              Evaluating live event telemetry across 10 Sigma-inspired detection rules with real-time multi-stage correlation.
            </p>
          </div>
        </div>

        <div className="flex items-center space-x-3 shrink-0">
          <button
            onClick={onNavigateToSimulation}
            className="flex items-center space-x-1.5 px-3 py-2 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold shadow-glow-cyan transition"
          >
            <Terminal className="w-4 h-4" />
            <span>Launch Simulation Lab</span>
          </button>
        </div>
      </div>

      {/* KPI Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-4">
        {/* Card 1 */}
        <div className="p-4 rounded-xl bg-navy-900 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Ingested Events</span>
            <Activity className="w-4 h-4 text-cyan-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {(analytics?.totalEvents || 0).toLocaleString()}
          </div>
          <div className="flex items-center space-x-1 text-[11px] text-emerald-400 mt-1 font-mono">
            <TrendingUp className="w-3 h-3" />
            <span>+14.2% / min</span>
          </div>
        </div>

        {/* Card 2 */}
        <div className="p-4 rounded-xl bg-navy-900 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Detected Threats</span>
            <Flame className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-amber-400">
            {analytics?.threatsDetected || 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">Sigma rule triggers</div>
        </div>

        {/* Card 3 */}
        <div 
          onClick={onNavigateToIncidents}
          className="p-4 rounded-xl bg-navy-900 border border-slate-800 hover:border-rose-500/50 cursor-pointer transition"
        >
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Open Incidents</span>
            <AlertTriangle className="w-4 h-4 text-rose-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-rose-400">
            {analytics?.openIncidents || 0}
          </div>
          <div className="flex items-center space-x-1 text-[11px] text-rose-300 mt-1 font-mono">
            <span>{analytics?.criticalIncidents || 0} Critical</span>
            <ArrowUpRight className="w-3 h-3" />
          </div>
        </div>

        {/* Card 4 */}
        <div className="p-4 rounded-xl bg-navy-900 border border-slate-800 hover:border-slate-700 transition">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Active IP Blocks</span>
            <ShieldBan className="w-4 h-4 text-cyan-accent" />
          </div>
          <div className="text-2xl font-bold font-mono text-cyan-accent">
            {analytics?.activeBlockedIps || 0}
          </div>
          <div className="text-[11px] text-slate-400 mt-1">SOAR firewall policies</div>
        </div>

        {/* Card 5 */}
        <div className="p-4 rounded-xl bg-navy-900 border border-slate-800 hover:border-slate-700 transition col-span-2 md:col-span-1">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Mean Time to Detect</span>
            <Clock className="w-4 h-4 text-blue-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white">
            {analytics?.meanTimeToDetectMinutes || 1.2}m
          </div>
          <div className="text-[11px] text-slate-400 mt-1">
            MTTR: {analytics?.meanTimeToRespondMinutes || 4.8}m
          </div>
        </div>
      </div>

      {/* Main Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Ingestion Velocity Chart */}
        <div className="lg:col-span-2 p-5 rounded-xl bg-navy-900 border border-slate-800 flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
                Telemetry Velocity & Threat Density
              </h3>
              <p className="text-[11px] text-slate-500">Security events and detection triggers over time</p>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-slate-800 text-cyan-400 border border-slate-700">
              Live Stream
            </span>
          </div>

          <div className="h-64 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={velocityData}>
                <defs>
                  <linearGradient id="eventGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#00F5FF" stopOpacity={0.3}/>
                    <stop offset="95%" stopColor="#00F5FF" stopOpacity={0}/>
                  </linearGradient>
                  <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#F43F5E" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#F43F5E" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <XAxis dataKey="time" stroke="#475569" fontSize={11} tickLine={false} />
                <YAxis stroke="#475569" fontSize={11} tickLine={false} />
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
                />
                <Area type="monotone" dataKey="events" stroke="#00F5FF" strokeWidth={2} fillOpacity={1} fill="url(#eventGradient)" name="Events" />
                <Area type="monotone" dataKey="threats" stroke="#F43F5E" strokeWidth={2} fillOpacity={1} fill="url(#threatGradient)" name="Threats" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Severity Breakdown Donut */}
        <div className="p-5 rounded-xl bg-navy-900 border border-slate-800 flex flex-col justify-between">
          <div className="mb-4">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              Threat Severity Distribution
            </h3>
            <p className="text-[11px] text-slate-500">Classification of active threat incidents</p>
          </div>

          <div className="h-52 w-full flex items-center justify-center">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={displaySeverityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={50}
                  outerRadius={75}
                  paddingAngle={4}
                  dataKey="value"
                >
                  {displaySeverityData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip 
                  contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="grid grid-cols-2 gap-2 pt-2 border-t border-slate-800/80 text-[11px]">
            {displaySeverityData.map((d) => (
              <div key={d.name} className="flex items-center space-x-1.5">
                <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ backgroundColor: d.color }}></span>
                <span className="text-slate-400 truncate">{d.name}:</span>
                <span className="text-slate-200 font-mono font-semibold">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Breakdown */}
      <div className="p-5 rounded-xl bg-navy-900 border border-slate-800">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300 font-mono">
              MITRE ATT&CK® Tactic Matrix Distribution
            </h3>
            <p className="text-[11px] text-slate-500">Observed adversary tactics mapped across correlated incidents</p>
          </div>
          <span className="text-[10px] text-slate-400 font-mono">Framework v14</span>
        </div>

        <div className="h-44 w-full">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={defaultMitre} layout="vertical" margin={{ top: 5, right: 30, left: 100, bottom: 5 }}>
              <XAxis type="number" stroke="#475569" fontSize={11} />
              <YAxis dataKey="tactic" type="category" stroke="#94A3B8" fontSize={11} tickLine={false} width={120} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#0B0F19', borderColor: '#1E293B', borderRadius: '8px', fontSize: '12px' }}
              />
              <Bar dataKey="count" fill="#06B6D4" radius={[0, 4, 4, 0]} name="Observations" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
};
