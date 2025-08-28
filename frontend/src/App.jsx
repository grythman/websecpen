import { useState } from 'react'
import reactLogo from './assets/react.svg'
import viteLogo from '/vite.svg'
import './App.css'
import { ThemeProvider } from './ThemeContext.jsx';
import Login from './components/Login.jsx';
import Dashboard from './components/Dashboard.jsx';

function App() {
  return (
    <ThemeProvider>
      <div>
        <Login />
        <Dashboard />
        {/* Integrate other components as per routing in later tasks */}
      </div>
    </ThemeProvider>
  );
}

export default App;
