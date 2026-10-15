import React, {useEffect, useState} from "react";
import {createRoot} from "react-dom/client";
import {ReactFlow, Background, Controls, MiniMap, useNodesState, useEdgesState} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import "./styles.css";

const logo="https://raw.githubusercontent.com/vishnunotnice/Portfolio/refs/heads/main/NetScope%20Logo%20Trasnperent.png";

function App(){
  const [nodes,setNodes,onNodesChange]=useNodesState([]); const [edges,setEdges,onEdgesChange]=useEdgesState([]); const [error,setError]=useState("");
  useEffect(()=>{fetch("/api/topology").then(r=>{if(!r.ok) throw new Error(`API returned ${r.status}`); return r.json()}).then(g=>{setNodes(g.nodes||[]);setEdges(g.edges||[])}).catch(e=>setError(e.message))},[]);
  return <main><header><img src={logo} alt="NetScope"/><div><p className="eyebrow">PHASE 2 / TOPOLOGY</p><h1>Visual network topology</h1><p className="muted">Observed assets and traceroute hops from the latest authorized scan.</p></div></header><section className="status">{error?`Unable to load topology: ${error}`:`${nodes.length} nodes · ${edges.length} observed edges`}</section><div className="canvas"><ReactFlow nodes={nodes} edges={edges} onNodesChange={onNodesChange} onEdgesChange={onEdgesChange} fitView><Background variant="dots" gap={22} size={1}/><Controls/><MiniMap/></ReactFlow></div></main>
}
createRoot(document.getElementById("root")).render(<App/>);
