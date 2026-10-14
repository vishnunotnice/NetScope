import React from 'react';
import {createRoot} from 'react-dom/client';
import ReactFlow, {Background, Controls, MiniMap} from 'reactflow';
import 'reactflow/dist/style.css';
import './styles.css';

function App(){const [graph,setGraph]=React.useState({nodes:[],edges:[]});React.useEffect(()=>{fetch('/api/topology').then(r=>r.json()).then(setGraph)},[]);return <main><header><img src="https://raw.githubusercontent.com/vishnunotnice/Portfolio/refs/heads/main/NetScope%20Logo%20Trasnperent.png"/><h1>NetScope</h1><span>NETWORK TOPOLOGY</span></header><section><ReactFlow nodes={graph.nodes} edges={graph.edges} fitView><Background color="#3f7cff" gap={24}/><Controls/><MiniMap/></ReactFlow></section></main>}
createRoot(document.getElementById('root')).render(<App/>);
