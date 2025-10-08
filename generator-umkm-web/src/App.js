import React from 'react';
import { Routes, Route } from 'react-router-dom';
import LoginPage from './LoginPage';
import RegisterPage from './RegisterPage';
import GeneratorPage from './GeneratorPage';
import { Toaster } from 'react-hot-toast';

function App() {
  return (
    <>
    <Toaster 
        position="top-center" 
        reverseOrder={false}
      />
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route path="/register" element={<RegisterPage />} />
       <Route path="/generator" element={<GeneratorPage />} /> {/* Halaman utama sekarang adalah generator */}
       {/* Rute utama sekarang mengarah ke Login */}
      <Route path="/" element={<LoginPage />} />
    </Routes>
    </>
  );
}


export default App;