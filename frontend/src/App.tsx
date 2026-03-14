import { Routes, Route } from "react-router-dom";
import Dashboard from "./pages/Dashboard";
import ScanView from "./pages/ScanView";
import Understanding from "./pages/Understanding";
import SpaceBackground from "./components/SpaceBackground";

function App() {
  return (
    <div className="min-h-screen relative">
      <SpaceBackground />
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/scan/:id" element={<ScanView />} />
        <Route path="/understanding" element={<Understanding />} />
      </Routes>
    </div>
  );
}

export default App;
