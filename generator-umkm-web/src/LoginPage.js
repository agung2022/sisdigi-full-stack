import React, { useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import axios from 'axios';
import toast from 'react-hot-toast';
import logo from "./assets/Logo-no-bg.png";

export default function LoginPage() {
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [isLoading, setIsLoading] = useState(false);
    const navigate = useNavigate();

    const handleLogin = async (e) => {
        e.preventDefault();
        setIsLoading(true);
        const loginPromise = axios.post('/api/auth/login', { email, password });

        toast.promise(loginPromise, {
            loading: 'Mencoba login...',
            success: (response) => {
                localStorage.setItem('accessToken', response.data.accessToken);
                navigate('/generator');
                return 'Login berhasil!';
            },
            error: (err) => err.response?.data?.message || 'Login gagal, silakan coba lagi.',
        });

        setIsLoading(false);
    };

    return (
        <div className="flex items-center justify-center min-h-screen bg-gradient-to-br from-indigo-100 to-white">
            <div className="w-full max-w-md px-8 py-10 space-y-8 bg-white rounded-2xl shadow-xl">
                <div className="text-center">
                    <img src={logo} alt="SisDigi UMKM Logo" className="w-24 h-24 mx-auto" />
                    <h1 className="mt-4 text-3xl font-bold text-gray-800">Login ke SisDigi UMKM</h1>
                    <p className="mt-2 text-sm text-gray-600">Masuk untuk melanjutkan</p>
                </div>
                
                <form onSubmit={handleLogin} className="space-y-6">
                    <div>
                        <label htmlFor="email" className="text-sm font-semibold text-gray-600">Alamat Email</label>
                        <input id="email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} required 
                               className="w-full px-4 py-3 mt-2 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-400 focus:outline-none transition" />
                    </div>
                    <div>
                        <label htmlFor="password" className="text-sm font-semibold text-gray-600">Password</label>
                        <input id="password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} required 
                               className="w-full px-4 py-3 mt-2 bg-gray-50 border border-gray-200 rounded-lg focus:ring-2 focus:ring-indigo-400 focus:outline-none transition" />
                    </div>
                    <button type="submit" disabled={isLoading}
                            className="w-full py-3 font-bold text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 focus:outline-none focus:ring-4 focus:ring-indigo-300 transition duration-300 disabled:bg-indigo-400 flex items-center justify-center">
                        {isLoading && <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>}
                        {isLoading ? 'Memverifikasi...' : 'Login'}
                    </button>
                </form>

                <p className="text-sm text-center text-gray-600">
                    Belum punya akun? <Link to="/register" className="font-semibold text-indigo-600 hover:underline">Daftar gratis</Link>
                </p>
            </div>
        </div>
    );
}
