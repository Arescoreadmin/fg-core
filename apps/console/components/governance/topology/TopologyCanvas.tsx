'use client';

import { useEffect, useRef } from 'react';
import type { GraphNode, GraphEdge } from '@/lib/governanceApi';

const NODE_TYPE_COLOR: Record<string, string> = {
  governance_asset:       '#3B82F6',
  ai_system:              '#8B5CF6',
  oauth_application:      '#F59E0B',
  enterprise_application: '#06B6D4',
  identity:               '#10B981',
  finding:                '#EF4444',
  control:                '#22C55E',
  scan:                   '#A855F7',
  engagement:             '#60A5FA',
  evidence:               '#14B8A6',
  vendor:                 '#F97316',
  department:             '#64748B',
};

const EDGE_TYPE_COLOR: Record<string, string> = {
  OWNS:           '#3B82F6',
  GOVERNED_BY:    '#22C55E',
  USES:           '#F59E0B',
  ACCESSES:       '#EF4444',
  CONNECTED_TO:   '#94A3B8',
  GENERATED:      '#A855F7',
  DETECTED_BY:    '#F97316',
  IMPACTS:        '#DC2626',
  ATTESTED_BY:    '#10B981',
  SUPPORTS:       '#06B6D4',
  RELATED_TO:     '#94A3B8',
  PROMOTED_FROM:  '#8B5CF6',
};

const CY_STYLE = [
  {
    selector: 'node',
    style: {
      'background-color': 'data(color)',
      'label': 'data(label)',
      'width': 'data(size)',
      'height': 'data(size)',
      'font-size': '10px',
      'color': '#F1F5F9',
      'text-valign': 'bottom',
      'text-halign': 'center',
      'text-margin-y': 4,
      'border-width': 1.5,
      'border-color': '#1E293B',
      'cursor': 'pointer',
    },
  },
  { selector: 'node.dead', style: { 'opacity': 0.3, 'background-color': '#94A3B8', 'border-color': '#475569' } },
  { selector: 'node.low-confidence', style: { 'opacity': 0.6, 'border-style': 'dashed' } },
  { selector: 'node.anomaly', style: { 'border-width': 3, 'border-color': '#EF4444' } },
  { selector: 'node.selected', style: { 'border-width': 3, 'border-color': '#06B6D4' } },
  { selector: 'node.highlighted', style: { 'border-width': 2, 'border-color': '#84CC16' } },
  { selector: 'node.dimmed', style: { 'opacity': 0.15 } },
  {
    selector: 'edge',
    style: {
      'width': 1.5,
      'line-color': 'data(color)',
      'target-arrow-color': 'data(color)',
      'target-arrow-shape': 'triangle',
      'curve-style': 'bezier',
      'opacity': 0.7,
      'cursor': 'pointer',
    },
  },
  { selector: 'edge:selected', style: { 'width': 3, 'opacity': 1 } },
];

export interface TopologyCanvasProps {
  nodes: GraphNode[];
  edges: GraphEdge[];
  anomalyNodeIds: Set<string>;
  highlightedNodeIds: Set<string>;
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  onNodeClick: (nodeId: string) => void;
  onEdgeClick: (edgeId: string) => void;
  highlightMode: boolean;
  showDeadNodes: boolean;
  minConfidence: number;
}

export function TopologyCanvas({
  nodes,
  edges,
  anomalyNodeIds,
  highlightedNodeIds,
  selectedNodeId,
  selectedEdgeId,
  onNodeClick,
  onEdgeClick,
  highlightMode,
}: TopologyCanvasProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const cyRef = useRef<any>(null); // cytoscape Core has no exported TS type suitable for refs

  useEffect(() => {
    if (!containerRef.current) return;

    let cy: typeof cyRef.current = null;

    import('cytoscape').then((mod) => {
      const cytoscape = mod.default;
      cy = cytoscape({
        container: containerRef.current,
        style: CY_STYLE as any,
        layout: { name: 'cose' },
        elements: [],
      });
      cyRef.current = cy;

      cy.on('tap', 'node', (evt: { target: { data: (k: string) => string } }) => {
        onNodeClick(evt.target.data('node_id'));
      });
      cy.on('tap', 'edge', (evt: { target: { data: (k: string) => string } }) => {
        onEdgeClick(evt.target.data('edge_id'));
      });
    });

    return () => {
      if (cy) cy.destroy();
      cyRef.current = null;
    };
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.elements().remove();

    const nodeElements = nodes.map((node) => ({
      group: 'nodes' as const,
      data: {
        id: node.node_id,
        label: node.label.length > 20 ? node.label.slice(0, 20) + '…' : node.label,
        node_id: node.node_id,
        node_type: node.node_type,
        color: NODE_TYPE_COLOR[node.node_type] ?? '#94A3B8',
        size: node.degree_centrality >= 5 ? 40 : 28,
      },
      classes: [
        node.trust_score === 0 ? 'dead' : '',
        anomalyNodeIds.has(node.node_id) ? 'anomaly' : '',
        node.confidence < 50 ? 'low-confidence' : '',
        selectedNodeId === node.node_id ? 'selected' : '',
        highlightedNodeIds.has(node.node_id) ? 'highlighted' : '',
        (highlightMode && !anomalyNodeIds.has(node.node_id)) ? 'dimmed' : '',
      ].filter(Boolean).join(' '),
    }));

    const edgeElements = edges.map((edge) => ({
      group: 'edges' as const,
      data: {
        id: edge.edge_id,
        source: edge.source_node_id,
        target: edge.target_node_id,
        edge_id: edge.edge_id,
        edge_type: edge.edge_type,
        color: EDGE_TYPE_COLOR[edge.edge_type] ?? '#94A3B8',
      },
    }));

    cy.add([...nodeElements, ...edgeElements]);

    cy.layout({
      name: 'cose',
      animate: false,
      randomize: false,
      nodeRepulsion: () => 8000,
      nodeOverlap: 20,
      gravity: 0.25,
      numIter: 1000,
    }).run();
  }, [nodes, edges, anomalyNodeIds, highlightedNodeIds, selectedNodeId, highlightMode]);

  useEffect(() => {
    const cy = cyRef.current;
    if (!cy) return;

    cy.nodes().forEach((n: { id: () => string; classes: (c: string) => void; removeClass: (c: string) => void; addClass: (c: string) => void; data: (k: string) => unknown }) => {
      const nodeId = n.id();
      const isAnomaly = anomalyNodeIds.has(nodeId);
      const isHighlighted = highlightedNodeIds.has(nodeId);
      const isSelected = nodeId === selectedNodeId;
      const isDimmed = highlightMode && !isAnomaly;

      n.removeClass('selected highlighted dimmed anomaly');
      if (isSelected) n.addClass('selected');
      if (isHighlighted) n.addClass('highlighted');
      if (isAnomaly) n.addClass('anomaly');
      if (isDimmed) n.addClass('dimmed');
    });

    cy.edges().forEach((e: { id: () => string; select: () => void; unselect: () => void }) => {
      if (e.id() === selectedEdgeId) {
        e.select();
      } else {
        e.unselect();
      }
    });
  }, [selectedNodeId, selectedEdgeId, highlightedNodeIds, anomalyNodeIds, highlightMode]);

  if (nodes.length === 0) {
    return (
      <div className="h-full w-full bg-slate-950 rounded-lg flex items-center justify-center">
        <p className="text-sm text-muted">No nodes match current filters</p>
      </div>
    );
  }

  return (
    <div className="h-full w-full bg-slate-950 rounded-lg">
      <div ref={containerRef} className="h-full w-full" />
    </div>
  );
}
