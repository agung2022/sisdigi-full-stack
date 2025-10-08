import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import toast from 'react-hot-toast';
import logo from "./assets/Logo-no-bg.png";

export default function RegisterPage() {
    const [name, setName] = useState('');
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleRegister = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        const registerPromise = axios.post('/api/auth/register', { name, email, password });
        
        toast.promise(registerPromise, {
            loading: 'Mendaftarkan akun...',
            success: () => {
                navigate('/login');
                return 'Registrasi berhasil! Silakan login.';
            },
            error: (err) => err.response?.data?.message || 'Registrasi gagal, silakan coba lagi.',
        });
        
        setIsLoading(false);
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-indigo-100 to-white">
            <div className="w-full max-w-md px-8 py-10 space-y-8 bg-white rounded-2xl shadow-xl">
                <div className="text-center">
                    <img src={logo} alt="SisDigi UMKM Logo" className="w-24 h-24 mx-auto" />
                    <h1 className="mt-4 text-3xl font-bold text-gray-800">Buat Akun Baru</h1>
                    <p className="mt-2 text-sm text-gray-600">Mulai perjalanan digital Anda</p>
                </div>
                
                <form onSubmit={handleRegister} className="space-y-6">
                    <div>
                        <label htmlFor="name" className="text-sm font-semibold text-gray-600">Nama Lengkap</label>
                        <input id="name" type="text" value={name} onChange={(e) => setName(e.target.value)} required 
                               className="w-full px-4 py-3 mt-2 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-400 focus:outline-none transition" />
                    </div>
                    <div>
                        <label htmlFor="email" className="text-sm font-semibold text-gray-600">Alamat Email</label>
                        <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required 
                               className="w-full px-4 py-3 mt-2 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-400 focus:outline-none transition" />
                    </div>
                    <div>
                        <label htmlFor="password" className="text-sm font-semibold text-gray-600">Password</label>
                        <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required minLength="6"
                               className="w-full px-4 py-3 mt-2 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-400 focus:outline-none transition" />
                    </div>
                    <button type="submit" disabled={isLoading}
                            className="w-full py-3 font-bold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-4 focus:ring-indigo-300 transition duration-300 disabled:bg-indigo-400 flex items-center justify-center">
                        {isLoading && <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>}
                        {isLoading ? 'Mendaftarkan...' : 'Daftar'}
                    </button>
                </form>

                <p className="text-sm text-center text-gray-600">
                    Sudah punya akun? <Link to="/login" className="font-semibold text-indigo-600 hover:underline">Masuk di sini</Link>
                </p>
            </div>
        </div>
    );
}
