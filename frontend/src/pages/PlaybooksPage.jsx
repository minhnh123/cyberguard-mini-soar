import React, { useEffect, useState, useCallback } from 'react';
import {
  ReactFlow,
  Controls,
  Background,
  applyNodeChanges,
  applyEdgeChanges,
  addEdge,
  Handle,
  Position
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { 
  Workflow, 
  Plus, 
  Save, 
  Trash2, 
  Code, 
  Play, 
  CheckCircle2, 
  ShieldAlert, 
  Brain, 
  Globe, 
  Terminal, 
  Lock, 
  Zap,
  Layers,
  Sparkles
} from 'lucide-react';
import { PlaybooksAPI } from '../services/api';

// Custom Node Component for Visual Flow
const CustomStepNode = ({ data, isConnectable }) => {
  const getIcon = (type) => {
    switch (type) {
      case 'trigger': return <Zap className="w-4 h-4 text-amber-400" />;
      case 'enrichment': return <Globe className="w-4 h-4 text-cyan-400" />;
      case 'ai_triage': return <Brain className="w-4 h-4 text-indigo-400" />;
      case 'human_approval': return <CheckCircle2 className="w-4 h-4 text-amber-400" />;
      case 'response_action': return <Terminal className="w-4 h-4 text-emerald-400" />;
      default: return <Workflow className="w-4 h-4 text-slate-400" />;
    }
  };

  const getBorderColor = (type) => {
    switch (type) {
      case 'trigger': return 'border-amber-500/50 shadow-amber-950/50';
      case 'enrichment': return 'border-cyan-500/50 shadow-cyan-950/50';
      case 'ai_triage': return 'border-indigo-500/50 shadow-indigo-950/50';
      case 'human_approval': return 'border-amber-500/50 shadow-amber-950/50';
      case 'response_action': return 'border-emerald-500/50 shadow-emerald-950/50';
      default: return 'border-slate-700 shadow-slate-950';
    }
  };

  return (
    <div className={`px-4 py-3 rounded-xl bg-slate-900 border ${getBorderColor(data.nodeType || 'step')} shadow-lg min-w-[220px] space-y-1.5`}>
      <Handle type="target" position={Position.Top} isConnectable={isConnectable} className="!bg-cyan-400 !w-2.5 !h-2.5" />
      <div className="flex items-center gap-2">
        <div className="p-1.5 rounded-lg bg-slate-950 border border-slate-800">
          {getIcon(data.nodeType)}
        </div>
        <div>
          <div className="text-[10px] uppercase font-mono font-bold text-slate-400">{data.nodeType || 'Action'}</div>
          <div className="text-xs font-bold text-slate-100">{data.label}</div>
        </div>
      </div>
      {data.description && (
        <div className="text-[11px] text-slate-400 leading-tight pt-1 border-t border-slate-800/80">
          {data.description}
        </div>
      )}
      <Handle type="source" position={Position.Bottom} isConnectable={isConnectable} className="!bg-cyan-400 !w-2.5 !h-2.5" />
    </div>
  );
};

const nodeTypes = {
  trigger: CustomStepNode,
  enrichment: CustomStepNode,
  ai_triage: CustomStepNode,
  human_approval: CustomStepNode,
  response_action: CustomStepNode,
};

export default function PlaybooksPage() {
  const [playbooks, setPlaybooks] = useState([]);
  const [selectedPlaybook, setSelectedPlaybook] = useState(null);
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [viewMode, setViewMode] = useState('visual'); // 'visual' | 'yaml'
  const [yamlText, setYamlText] = useState('');
  const [saving, setSaving] = useState(false);

  const loadPlaybooks = async () => {
    try {
      const data = await PlaybooksAPI.list();
      setPlaybooks(data);
      if (data.length > 0 && !selectedPlaybook) {
        selectPlaybook(data[0]);
      }
    } catch (err) {
      console.error(err);
    }
  };

  useEffect(() => {
    loadPlaybooks();
  }, []);

  const selectPlaybook = (pb) => {
    setSelectedPlaybook(pb);
    setYamlText(pb.yaml_definition || '');

    const graph = pb.graph_data || {};
    const rawNodes = graph.nodes || [];
    const rawEdges = graph.edges || [];

    // Map raw nodes into ReactFlow format with nodeType attached
    const mappedNodes = rawNodes.map((n, i) => ({
      id: n.id || `node_${i+1}`,
      type: n.type || 'enrichment',
      position: n.position || { x: 250, y: i * 120 + 50 },
      data: {
        label: n.data?.label || n.name || 'Step',
        nodeType: n.type || 'enrichment',
        description: n.data?.description || ''
      }
    }));

    setNodes(mappedNodes);
    setEdges(rawEdges);
  };

  const onNodesChange = useCallback(
    (changes) => setNodes((nds) => applyNodeChanges(changes, nds)),
    []
  );

  const onEdgesChange = useCallback(
    (changes) => setEdges((eds) => applyEdgeChanges(changes, eds)),
    []
  );

  const onConnect = useCallback(
    (params) => setEdges((eds) => addEdge(params, eds)),
    []
  );

  const handleAddNode = (type, label, description) => {
    const newId = `node_${Date.now().toString().slice(-4)}`;
    const yPos = nodes.length > 0 ? Math.max(...nodes.map(n => n.position.y)) + 140 : 50;
    const newNode = {
      id: newId,
      type: type,
      position: { x: 250, y: yPos },
      data: {
        label,
        nodeType: type,
        description
      }
    };
    setNodes([...nodes, newNode]);
    if (nodes.length > 0) {
      const lastNode = nodes[nodes.length - 1];
      setEdges([...edges, { id: `e-${lastNode.id}-${newId}`, source: lastNode.id, target: newId }]);
    }
  };

  const handleSave = async () => {
    if (!selectedPlaybook) return;
    try {
      setSaving(true);
      const graphData = {
        nodes: nodes.map(n => ({
          id: n.id,
          type: n.type,
          position: n.position,
          data: n.data
        })),
        edges: edges
      };

      await PlaybooksAPI.update(selectedPlaybook.id, {
        name: selectedPlaybook.name,
        category: selectedPlaybook.category,
        is_active: selectedPlaybook.is_active,
        graph_data: graphData,
        yaml_definition: yamlText
      });

      await loadPlaybooks();
      alert('Playbook updated successfully!');
    } catch (err) {
      alert(`Save error: ${err.message}`);
    } finally {
      setSaving(false);
    }
  };

  const handleCreateNew = async () => {
    const name = prompt('Enter Playbook Name:', 'New Custom Security Playbook');
    if (!name) return;

    try {
      const newPb = await PlaybooksAPI.create({
        name,
        category: 'generic',
        is_active: true,
        graph_data: {
          nodes: [
            { id: 'node_1', type: 'trigger', position: { x: 250, y: 50 }, data: { label: 'Alert Trigger', nodeType: 'trigger', description: 'Ingest alert' } },
            { id: 'node_2', type: 'ai_triage', position: { x: 250, y: 180 }, data: { label: 'AI Triage', nodeType: 'ai_triage', description: 'Analyze & score' } },
            { id: 'node_3', type: 'human_approval', position: { x: 250, y: 310 }, data: { label: 'Approval Gateway', nodeType: 'human_approval', description: 'Analyst approval' } }
          ],
          edges: [
            { id: 'e1-2', source: 'node_1', target: 'node_2' },
            { id: 'e2-3', source: 'node_2', target: 'node_3' }
          ]
        }
      });
      await loadPlaybooks();
      selectPlaybook(newPb);
    } catch (err) {
      alert(`Error creating playbook: ${err.message}`);
    }
  };

  return (
    <div className="p-6 max-w-7xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="p-4 rounded-xl bg-slate-900 border border-slate-800 flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h2 className="text-base font-bold text-slate-100 flex items-center gap-2">
            <Workflow className="w-5 h-5 text-cyan-400" />
            Visual Playbook Builder & DAG Orchestrator
          </h2>
          <p className="text-xs text-slate-400 mt-0.5">
            Design incident response workflows with graphical node drag-and-drop or synchronized YAML code.
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={handleCreateNew}
            className="px-3 py-1.5 rounded-lg bg-cyan-500/20 hover:bg-cyan-500/30 text-cyan-300 border border-cyan-500/40 text-xs font-semibold flex items-center gap-1.5 transition"
          >
            <Plus className="w-4 h-4" />
            <span>New Playbook</span>
          </button>

          <button
            onClick={handleSave}
            disabled={saving}
            className="px-4 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-bold flex items-center gap-1.5 shadow-lg shadow-cyan-500/20 transition"
          >
            <Save className="w-4 h-4" />
            <span>{saving ? 'Saving...' : 'Save Playbook'}</span>
          </button>
        </div>
      </div>

      {/* Main Layout: Left Playbooks List, Right Canvas */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 h-[720px]">
        {/* Playbooks Sidebar */}
        <div className="glass-panel p-4 rounded-xl border border-slate-800 flex flex-col space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-slate-400">
            Available Playbooks ({playbooks.length})
          </div>

          <div className="space-y-2 flex-1 overflow-y-auto">
            {playbooks.map((pb) => (
              <button
                key={pb.id}
                onClick={() => selectPlaybook(pb)}
                className={`w-full text-left p-3 rounded-xl border transition space-y-1 ${
                  selectedPlaybook?.id === pb.id
                    ? 'bg-cyan-500/10 border-cyan-500/40 shadow-sm shadow-cyan-950'
                    : 'bg-slate-900/60 border-slate-800 hover:bg-slate-900'
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="font-semibold text-xs text-slate-200 truncate">{pb.name}</span>
                  <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                    pb.is_active ? 'bg-emerald-500/20 text-emerald-300' : 'bg-slate-800 text-slate-500'
                  }`}>
                    {pb.is_active ? 'ACTIVE' : 'OFF'}
                  </span>
                </div>
                <div className="text-[11px] text-slate-400 line-clamp-2">
                  {pb.description || 'Custom response sequence.'}
                </div>
              </button>
            ))}
          </div>

          {/* Quick Node Adder Palette */}
          <div className="p-3 rounded-lg bg-slate-900/90 border border-slate-800 space-y-2">
            <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-400">
              + Add Step Node
            </div>
            <div className="grid grid-cols-2 gap-1.5">
              <button
                onClick={() => handleAddNode('enrichment', 'Threat Intel Lookup', 'Query IP-API / VirusTotal')}
                className="p-1.5 rounded bg-slate-800 hover:bg-cyan-950/60 hover:text-cyan-300 border border-slate-700 text-[11px] text-left transition flex items-center gap-1"
              >
                <Globe className="w-3 h-3 text-cyan-400" />
                <span>Enrich Intel</span>
              </button>

              <button
                onClick={() => handleAddNode('ai_triage', 'AI Triage & MITRE', 'Analyze severity & tactics')}
                className="p-1.5 rounded bg-slate-800 hover:bg-indigo-950/60 hover:text-indigo-300 border border-slate-700 text-[11px] text-left transition flex items-center gap-1"
              >
                <Brain className="w-3 h-3 text-indigo-400" />
                <span>AI Reasoner</span>
              </button>

              <button
                onClick={() => handleAddNode('human_approval', 'Approval Gateway', 'Analyst 1-click verify')}
                className="p-1.5 rounded bg-slate-800 hover:bg-amber-950/60 hover:text-amber-300 border border-slate-700 text-[11px] text-left transition flex items-center gap-1"
              >
                <CheckCircle2 className="w-3 h-3 text-amber-400" />
                <span>Approval Gate</span>
              </button>

              <button
                onClick={() => handleAddNode('response_action', 'Firewall Block', 'Execute netsh / iptables rule')}
                className="p-1.5 rounded bg-slate-800 hover:bg-emerald-950/60 hover:text-emerald-300 border border-slate-700 text-[11px] text-left transition flex items-center gap-1"
              >
                <Terminal className="w-3 h-3 text-emerald-400" />
                <span>Action Exec</span>
              </button>
            </div>
          </div>
        </div>

        {/* Right Canvas Area */}
        <div className="lg:col-span-3 glass-panel rounded-xl border border-slate-800 flex flex-col overflow-hidden">
          {/* Canvas Controls */}
          <div className="p-3 border-b border-slate-800 bg-slate-950/60 flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="font-semibold text-xs text-slate-200">
                {selectedPlaybook ? selectedPlaybook.name : 'Select a playbook'}
              </span>
            </div>

            <div className="flex items-center gap-2">
              <div className="flex rounded-lg bg-slate-900 p-1 border border-slate-800 text-xs">
                <button
                  onClick={() => setViewMode('visual')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    viewMode === 'visual' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'
                  }`}
                >
                  Visual Canvas
                </button>
                <button
                  onClick={() => setViewMode('yaml')}
                  className={`px-3 py-1 rounded font-medium transition ${
                    viewMode === 'yaml' ? 'bg-cyan-500 text-slate-950 font-bold' : 'text-slate-400'
                  }`}
                >
                  YAML Code
                </button>
              </div>
            </div>
          </div>

          {/* Canvas or Code Editor */}
          <div className="flex-1 bg-slate-950 relative">
            {viewMode === 'visual' ? (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                nodeTypes={nodeTypes}
                onNodesChange={onNodesChange}
                onEdgesChange={onEdgesChange}
                onConnect={onConnect}
                fitView
                className="bg-slate-950"
              >
                <Background color="#1e293b" gap={16} />
                <Controls className="!bg-slate-900 !border-slate-800 !text-slate-300" />
              </ReactFlow>
            ) : (
              <div className="h-full p-4">
                <textarea
                  value={yamlText}
                  onChange={(e) => setYamlText(e.target.value)}
                  className="w-full h-full p-4 rounded-xl bg-slate-900 border border-slate-800 font-mono text-xs text-cyan-300 focus:outline-none focus:border-cyan-500 leading-relaxed resize-none"
                  placeholder="Paste or write Playbook YAML definition here..."
                />
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
