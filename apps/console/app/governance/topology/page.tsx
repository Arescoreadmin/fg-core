'use client';

import { useCallback, useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import {
  listNodes,
  listEdges,
  getStats,
  listAnomalies,
  getCoverage,
  getNode,
  rebuildGraph,
  resolveAnomaly,
  type GraphNode,
  type GraphEdge,
  type GraphStats,
  type AnomalyResponse,
  type CoverageResponse,
} from '@/lib/governanceApi';
import { SnapshotDriftBadge } from '@/components/governance/topology/SnapshotDriftBadge';
import { RiskHighlighter } from '@/components/governance/topology/RiskHighlighter';
import { TopologyFilters, type TopologyFilters as TFilters } from '@/components/governance/topology/TopologyFilters';
import { TopologyCanvas } from '@/components/governance/topology/TopologyCanvas';
import { NodeInspector } from '@/components/governance/topology/NodeInspector';
import { EdgeInspector } from '@/components/governance/topology/EdgeInspector';
import { ProvenanceViewer } from '@/components/governance/topology/ProvenanceViewer';
import { ImpactAnalysis } from '@/components/governance/topology/ImpactAnalysis';
import { AnomalyQueryPanel } from '@/components/governance/topology/AnomalyQueryPanel';
import { PathFinder } from '@/components/governance/topology/PathFinder';
import { CoveragePanel } from '@/components/governance/topology/CoveragePanel';
import { cn } from '@/lib/cn';

const ALL_NODE_TYPES = [
  'governance_asset', 'ai_system', 'oauth_application', 'enterprise_application',
  'identity', 'finding', 'control', 'scan', 'engagement', 'evidence', 'vendor', 'department',
];

const ALL_EDGE_TYPES = [
  'OWNS', 'GOVERNED_BY', 'USES', 'ACCESSES', 'CONNECTED_TO', 'GENERATED',
  'DETECTED_BY', 'IMPACTS', 'ATTESTED_BY', 'SUPPORTS', 'RELATED_TO', 'PROMOTED_FROM',
];

type LeftPanel = 'anomalies' | 'pathfinder' | 'coverage';
type RightPanel = 'node' | 'edge' | 'lineage' | 'impact' | null;

function LoadingSpinner() {
  return <Loader2 className="h-6 w-6 animate-spin text-muted" />;
}

function ErrorBanner({ error }: { error: string }) {
  return (
    <div className="absolute inset-x-0 top-0 z-20 flex items-center gap-2 border-b border-risk-critical/40 bg-risk-critical/10 px-4 py-2 text-xs text-risk-critical">
      {error}
    </div>
  );
}

export default function GovernanceTopologyPage() {
  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [edges, setEdges] = useState<GraphEdge[]>([]);
  const [stats, setStats] = useState<GraphStats | null>(null);
  const [anomalies, setAnomalies] = useState<AnomalyResponse[]>([]);
  const [coverage, setCoverage] = useState<CoverageResponse | null>(null);
  const [coverageFramework, setCoverageFramework] = useState('NIST-AI-RMF');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedNodeId, setSelectedNodeId] = useState<string | null>(null);
  const [selectedEdgeId, setSelectedEdgeId] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<GraphNode | null>(null);
  const [selectedEdge, setSelectedEdge] = useState<GraphEdge | null>(null);
  const [sourceNode, setSourceNode] = useState<GraphNode | null>(null);
  const [targetNode, setTargetNode] = useState<GraphNode | null>(null);
  const [highlightedNodeIds, setHighlightedNodeIds] = useState<Set<string>>(new Set());
  const [anomalyNodeIds, setAnomalyNodeIds] = useState<Set<string>>(new Set());
  const [highlightMode, setHighlightMode] = useState(false);
  const [rebuilding, setRebuilding] = useState(false);
  const [resolvingAnomaly, setResolvingAnomaly] = useState<string | null>(null);
  const [rightPanel, setRightPanel] = useState<RightPanel>(null);
  const [leftPanel, setLeftPanel] = useState<LeftPanel>('anomalies');
  const [filters, setFilters] = useState<TFilters>({
    nodeType: '', edgeType: '', minConfidence: 0, showDeadNodes: true,
  });

  const loadAll = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [n, e, s, a, c] = await Promise.all([
        listNodes({ node_type: filters.nodeType || undefined }),
        listEdges({ edge_type: filters.edgeType || undefined }),
        getStats(),
        listAnomalies({ active_only: false }),
        getCoverage(coverageFramework),
      ]);
      setNodes(n);
      setEdges(e);
      setStats(s);
      setAnomalies(a);
      setCoverage(c);
      const ids = new Set<string>();
      for (const anomaly of a) {
        if (anomaly.is_active) {
          for (const id of anomaly.node_ids) ids.add(id);
        }
      }
      setAnomalyNodeIds(ids);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load topology data');
    } finally {
      setLoading(false);
    }
  }, [filters.nodeType, filters.edgeType, coverageFramework]);

  useEffect(() => {
    loadAll();
  }, [loadAll]);

  const loadAnomalies = useCallback(async () => {
    try {
      const a = await listAnomalies({ active_only: false });
      setAnomalies(a);
      const ids = new Set<string>();
      for (const anomaly of a) {
        if (anomaly.is_active) {
          for (const id of anomaly.node_ids) ids.add(id);
        }
      }
      setAnomalyNodeIds(ids);
    } catch {
      // non-critical reload
    }
  }, []);

  const handleFilterChange = useCallback((f: TFilters) => {
    setFilters(f);
  }, []);

  const handleNodeClick = useCallback(async (nodeId: string) => {
    setSelectedNodeId(nodeId);
    setSelectedEdgeId(null);
    setSelectedEdge(null);
    setRightPanel('node');
    try {
      const detail = await getNode(nodeId);
      setSelectedNode(detail.node);
    } catch {
      const fallback = nodes.find(n => n.node_id === nodeId) ?? null;
      setSelectedNode(fallback);
    }
  }, [nodes]);

  const handleEdgeClick = useCallback((edgeId: string) => {
    setSelectedEdgeId(edgeId);
    setSelectedNodeId(null);
    setSelectedNode(null);
    const edge = edges.find(e => e.edge_id === edgeId) ?? null;
    setSelectedEdge(edge);
    if (edge) {
      setSourceNode(nodes.find(n => n.node_id === edge.source_node_id) ?? null);
      setTargetNode(nodes.find(n => n.node_id === edge.target_node_id) ?? null);
    }
    setRightPanel('edge');
  }, [edges, nodes]);

  const handleRebuild = useCallback(async () => {
    setRebuilding(true);
    try {
      await rebuildGraph('ui_rebuild');
      await loadAll();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Rebuild failed');
    } finally {
      setRebuilding(false);
    }
  }, [loadAll]);

  const handleResolveAnomaly = useCallback(async (anomalyId: string) => {
    setResolvingAnomaly(anomalyId);
    try {
      await resolveAnomaly(anomalyId);
      await loadAnomalies();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to resolve anomaly');
    } finally {
      setResolvingAnomaly(null);
    }
  }, [loadAnomalies]);

  const handleFrameworkChange = useCallback(async (f: string) => {
    setCoverageFramework(f);
    try {
      const c = await getCoverage(f);
      setCoverage(c);
    } catch {
      setCoverage(null);
    }
  }, []);

  const filteredNodes = nodes.filter(n => {
    if (!filters.showDeadNodes && n.trust_score === 0) return false;
    if (filters.nodeType && n.node_type !== filters.nodeType) return false;
    if (n.confidence < filters.minConfidence) return false;
    return true;
  });

  const visibleNodeIds = new Set(filteredNodes.map(n => n.node_id));

  const filteredEdges = edges.filter(e => {
    if (filters.edgeType && e.edge_type !== filters.edgeType) return false;
    if (!visibleNodeIds.has(e.source_node_id) || !visibleNodeIds.has(e.target_node_id)) return false;
    return true;
  });

  const tabBtn = (panel: LeftPanel, label: string) => (
    <button
      onClick={() => setLeftPanel(panel)}
      className={cn(
        'flex-1 px-2 py-2 text-xs font-medium transition',
        leftPanel === panel
          ? 'border-b-2 border-foreground text-foreground'
          : 'text-muted hover:text-foreground',
      )}
    >
      {label}
    </button>
  );

  return (
    <div className="flex h-screen flex-col bg-background">
      <header className="flex items-center gap-4 border-b px-4 py-2">
        <h1 className="text-sm font-semibold text-foreground">Governance Topology</h1>
        <div className="flex-1" />
        <SnapshotDriftBadge
          stats={stats}
          loading={loading}
          onRebuild={handleRebuild}
          rebuilding={rebuilding}
        />
        <RiskHighlighter
          active={highlightMode}
          onChange={setHighlightMode}
          anomalyCount={anomalies.filter(a => a.is_active).length}
        />
      </header>

      <div className="border-b px-4 py-2">
        <TopologyFilters
          nodeTypes={ALL_NODE_TYPES}
          edgeTypes={ALL_EDGE_TYPES}
          filters={filters}
          onChange={handleFilterChange}
        />
      </div>

      <div className="flex flex-1 overflow-hidden">
        <aside className="w-72 shrink-0 border-r overflow-y-auto bg-surface-2">
          <div className="flex border-b border-border">
            {tabBtn('anomalies', 'Anomalies')}
            {tabBtn('pathfinder', 'Path Finder')}
            {tabBtn('coverage', 'Coverage')}
          </div>
          <div className="p-3">
            {leftPanel === 'anomalies' && (
              <AnomalyQueryPanel
                anomalies={anomalies}
                loading={loading}
                onHighlight={setHighlightedNodeIds}
                onResolve={handleResolveAnomaly}
                resolving={resolvingAnomaly}
              />
            )}
            {leftPanel === 'pathfinder' && (
              <PathFinder nodes={nodes} onHighlightPath={setHighlightedNodeIds} />
            )}
            {leftPanel === 'coverage' && (
              <CoveragePanel
                coverage={coverage}
                loading={loading}
                onFrameworkChange={handleFrameworkChange}
                framework={coverageFramework}
              />
            )}
          </div>
        </aside>

        <main className="flex-1 overflow-hidden relative">
          {loading && (
            <div className="absolute inset-0 flex items-center justify-center bg-slate-950/80 z-10">
              <LoadingSpinner />
            </div>
          )}
          {error && <ErrorBanner error={error} />}
          <TopologyCanvas
            nodes={filteredNodes}
            edges={filteredEdges}
            anomalyNodeIds={anomalyNodeIds}
            highlightedNodeIds={highlightedNodeIds}
            selectedNodeId={selectedNodeId}
            selectedEdgeId={selectedEdgeId}
            onNodeClick={handleNodeClick}
            onEdgeClick={handleEdgeClick}
            highlightMode={highlightMode}
            showDeadNodes={filters.showDeadNodes}
            minConfidence={filters.minConfidence}
          />
        </main>

        {rightPanel && (
          <aside className="w-80 shrink-0 border-l overflow-y-auto bg-surface-2">
            {rightPanel === 'node' && selectedNode && (
              <NodeInspector
                node={selectedNode}
                onClose={() => setRightPanel(null)}
                onShowLineage={() => setRightPanel('lineage')}
                onAnalyzeImpact={(_nodeId: string) => setRightPanel('impact')}
              />
            )}
            {rightPanel === 'edge' && (
              <EdgeInspector
                edge={selectedEdge}
                sourceNode={sourceNode}
                targetNode={targetNode}
                onClose={() => setRightPanel(null)}
              />
            )}
            {rightPanel === 'lineage' && (
              <div className="p-3">
                <div className="flex items-center justify-between mb-3">
                  <h3 className="text-sm font-semibold text-foreground">Lineage</h3>
                  <button
                    onClick={() => setRightPanel('node')}
                    className="text-xs text-muted hover:text-foreground"
                  >
                    ← Back
                  </button>
                </div>
                <ProvenanceViewer nodeId={selectedNodeId} />
              </div>
            )}
            {rightPanel === 'impact' && selectedNode && (
              <ImpactAnalysis
                nodeId={selectedNodeId}
                nodeLabel={selectedNode.label}
                onClose={() => setRightPanel('node')}
              />
            )}
          </aside>
        )}
      </div>
    </div>
  );
}
