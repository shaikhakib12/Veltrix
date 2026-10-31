import React, { useState, useEffect, useCallback } from 'react';
import { Header } from './components/common/Header.js';
import { Sidebar, NavTab } from './components/common/Sidebar.js';
import { DashboardOverview } from './pages/DashboardOverview.js';
import { LiveEvents } from './pages/LiveEvents.js';
import { ThreatDetection } from './pages/ThreatDetection.js';
import { Incidents } from './pages/Incidents.js';
import { ThreatIntelligence } from './pages/ThreatIntelligence.js';
import { ResponseCenter } from './pages/ResponseCenter.js';
import { SimulationLab } from './pages/SimulationLab.js';
import { AuditLogs } from './pages/AuditLogs.js';
import { Settings } from './pages/Settings.js';
import { api } from './services/api.js';
import { 
  SecurityEvent, 
  DetectionRule, 
  Incident, 
  ThreatIndicator, 
  ResponseExecution, 
  AuditRecord, 
  SimulationScenario 
} from './types/index.js';

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<NavTab>('overview');
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isResetting, setIsResetting] = useState<boolean>(false);

  // Core Data States
  const [analytics, setAnalytics] = useState<{
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
  } | null>(null);

  const [events, setEvents] = useState<SecurityEvent[]>([]);
  const [rules, setRules] = useState<DetectionRule[]>([]);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<Incident | null>(null);
  const [indicators, setIndicators] = useState<ThreatIndicator[]>([]);
  const [pendingApprovals, setPendingApprovals] = useState<ResponseExecution[]>([]);
  const [activeBlockedIps, setActiveBlockedIps] = useState<string[]>([]);
  const [suspendedUsers, setSuspendedUsers] = useState<string[]>([]);
  const [responseHistory, setResponseHistory] = useState<ResponseExecution[]>([]);
  const [auditLogs, setAuditLogs] = useState<AuditRecord[]>([]);
  const [scenarios, setScenarios] = useState<SimulationScenario[]>([]);

  // Refresh all platform telemetry from backend
  const refreshData = useCallback(async () => {
    try {
      const [
        analyticsRes,
        eventsRes,
        rulesRes,
        incidentsRes,
        indicatorsRes,
        approvalsRes,
        historyRes,
        auditRes,
        scenariosRes,
      ] = await Promise.all([
        api.getAnalyticsOverview().catch(() => null),
        api.getEvents({ limit: 100 }).catch(() => ({ total: 0, events: [] })),
        api.getDetectionRules().catch(() => ({ rules: [] })),
        api.getIncidents().catch(() => ({ total: 0, incidents: [] })),
        api.getThreatIndicators().catch(() => ({ indicators: [] })),
        api.getPendingApprovals().catch(() => ({ pendingApprovals: [] })),
        api.getResponseHistory().catch(() => ({ activeBlockedIps: [], suspendedUsers: [], history: [] })),
        api.getAuditLogs().catch(() => ({ total: 0, logs: [] })),
        api.getSimulationScenarios().catch(() => ({ scenarios: [] })),
      ]);

      if (analyticsRes) setAnalytics(analyticsRes);
      if (eventsRes?.events) setEvents(eventsRes.events);
      if (rulesRes?.rules) setRules(rulesRes.rules);
      if (incidentsRes?.incidents) {
        setIncidents(incidentsRes.incidents);
        // Retain or select active incident
        if (selectedIncident) {
          const updated = incidentsRes.incidents.find(i => i.incidentId === selectedIncident.incidentId);
          if (updated) setSelectedIncident(updated);
        } else if (incidentsRes.incidents.length > 0) {
          setSelectedIncident(incidentsRes.incidents[0]);
        }
      }
      if (indicatorsRes?.indicators) setIndicators(indicatorsRes.indicators);
      if (approvalsRes?.pendingApprovals) setPendingApprovals(approvalsRes.pendingApprovals);
      if (historyRes) {
        setActiveBlockedIps(historyRes.activeBlockedIps || []);
        setSuspendedUsers(historyRes.suspendedUsers || []);
        setResponseHistory(historyRes.history || []);
      }
      if (auditRes?.logs) setAuditLogs(auditRes.logs);
      if (scenariosRes?.scenarios) setScenarios(scenariosRes.scenarios);
    } catch (err) {
      console.error('Failed to load telemetry data:', err);
    }
  }, [selectedIncident]);

  useEffect(() => {
    refreshData();
    // Auto-poll every 4 seconds for live SOC telemetry
    const interval = setInterval(refreshData, 4000);
    return () => clearInterval(interval);
  }, [refreshData]);

  // Handlers
  const handleToggleRule = async (ruleId: string, currentEnabled: boolean) => {
    await api.updateDetectionRule(ruleId, { enabled: !currentEnabled });
    await refreshData();
  };

  const handleUpdateThreshold = async (ruleId: string, threshold: number) => {
    await api.updateDetectionRule(ruleId, { threshold });
    await refreshData();
  };

  const handleUpdateIncidentStatus = async (incidentId: string, status: string) => {
    await api.updateIncident(incidentId, { status });
    await refreshData();
  };

  const handleAddIncidentNote = async (incidentId: string, note: string) => {
    await api.updateIncident(incidentId, { note });
    await refreshData();
  };

  const handleExecuteResponse = async (incidentId: string, action: string) => {
    await api.executeResponse(incidentId, action);
    await refreshData();
  };

  const handleApproveResponse = async (executionId: string) => {
    await api.approveResponse(executionId);
    await refreshData();
  };

  const handleRollbackResponse = async (executionId: string) => {
    await api.rollbackResponse(executionId);
    await refreshData();
  };

  const handleExecuteSimulation = async (scenarioId: string) => {
    const res = await api.executeSimulation(scenarioId);
    await refreshData();
    return res;
  };

  const handleResetSimulation = async () => {
    setIsResetting(true);
    try {
      await api.resetSimulation();
      setSelectedIncident(null);
      await refreshData();
    } finally {
      setIsResetting(false);
    }
  };

  const handleNavigateToIncident = (incidentId: string) => {
    const target = incidents.find(i => i.incidentId === incidentId);
    if (target) setSelectedIncident(target);
    setActiveTab('incidents');
  };

  return (
    <div className="min-h-screen flex flex-col bg-navy-950 text-slate-100 font-sans">
      <Header onReset={handleResetSimulation} isResetting={isResetting} />

      <div className="flex-1 flex overflow-hidden">
        <Sidebar
          activeTab={activeTab}
          onSelectTab={setActiveTab}
          openIncidentsCount={incidents.filter(i => i.status !== 'RESOLVED' && i.status !== 'FALSE_POSITIVE').length}
          pendingApprovalsCount={pendingApprovals.length}
        />

        <main className="flex-1 overflow-y-auto p-6 bg-[#0B0F19]">
          <div className="max-w-7xl mx-auto">
            {activeTab === 'overview' && (
              <DashboardOverview
                analytics={analytics}
                onNavigateToSimulation={() => setActiveTab('simulation')}
                onNavigateToIncidents={() => setActiveTab('incidents')}
              />
            )}

            {activeTab === 'events' && (
              <LiveEvents
                events={events}
                onRefresh={refreshData}
                isLoading={isLoading}
              />
            )}

            {activeTab === 'detection' && (
              <ThreatDetection
                rules={rules}
                onToggleRule={handleToggleRule}
                onUpdateThreshold={handleUpdateThreshold}
              />
            )}

            {activeTab === 'incidents' && (
              <Incidents
                incidents={incidents}
                onUpdateStatus={handleUpdateIncidentStatus}
                onAddNote={handleAddIncidentNote}
                onExecuteResponse={handleExecuteResponse}
                selectedIncident={selectedIncident}
                onSelectIncident={setSelectedIncident}
              />
            )}

            {activeTab === 'threat-intel' && (
              <ThreatIntelligence indicators={indicators} />
            )}

            {activeTab === 'response' && (
              <ResponseCenter
                pendingApprovals={pendingApprovals}
                activeBlockedIps={activeBlockedIps}
                suspendedUsers={suspendedUsers}
                responseHistory={responseHistory}
                onApprove={handleApproveResponse}
                onRollback={handleRollbackResponse}
              />
            )}

            {activeTab === 'simulation' && (
              <SimulationLab
                scenarios={scenarios}
                onExecuteScenario={handleExecuteSimulation}
                onNavigateToIncident={handleNavigateToIncident}
                onReset={handleResetSimulation}
                isResetting={isResetting}
              />
            )}

            {activeTab === 'audit' && (
              <AuditLogs
                logs={auditLogs}
                onVerifyChain={api.verifyAuditChain}
                isLoading={isLoading}
              />
            )}

            {activeTab === 'settings' && <Settings />}
          </div>
        </main>
      </div>
    </div>
  );
};
