import React, { useState, useRef, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import axios from "axios";
import toast from "react-hot-toast";
import ConfirmationModal from "./ConfirmationModal";
import logo from './assets/Logo-no-bg.png';

// --- Komponen Ikon (lengkap) ---

const UploadIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="24"
    height="24"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" />
    <polyline points="17 8 12 3 7 8" />
    <line x1="12" x2="12" y1="3" y2="15" />
  </svg>
);
const LogoutIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="20"
    height="20"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4" />
    <polyline points="16 17 21 12 16 7" />
    <line x1="21" x2="9" y1="12" y2="12" />
  </svg>
);
const TrashIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <polyline points="3 6 5 6 21 6" />
    <path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" />
    <line x1="10" y1="11" x2="10" y2="17" />
    <line x1="14" y1="11" x2="14" y2="17" />
  </svg>
);
const CopyIcon = () => (
  <svg
    xmlns="http://www.w3.org/2000/svg"
    width="16"
    height="16"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    strokeWidth="2"
    strokeLinecap="round"
    strokeLinejoin="round"
  >
    <rect width="14" height="14" x="8" y="8" rx="2" ry="2" />
    <path d="M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2" />
  </svg>
);

export default function GeneratorPage() {
  const navigate = useNavigate();
  const [prompt, setPrompt] = useState("");
  const [generatedHtml, setGeneratedHtml] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [uploadedImages, setUploadedImages] = useState([]);
  const [history, setHistory] = useState([]);
  const [activeHistoryId, setActiveHistoryId] = useState(null);
  const fileInputRef = useRef(null);
  const [publishedUrl, setPublishedUrl] = useState("");
  const [publishedId, setPublishedId] = useState(null);
  const [modalState, setModalState] = useState({
    isOpen: false,
    title: "",
    message: "",
    onConfirm: () => {},
  });
  
  const fetchUserData = async () => {
    const api = createApiInstance();
    if (!api) return;
    try {
      const response = await api.get("/api/auth/me");
      if (response.data.published_url) {
        setPublishedUrl(response.data.published_url);
        setPublishedId(response.data.published_generation_id);
      }
    } catch (error) {
      console.error("Gagal mengambil data user:", error);
    }
  };

  const createApiInstance = () => {
    const token = localStorage.getItem("accessToken");
    if (!token) {
      navigate("/login");
      return null;
    }
    return axios.create({
      baseURL: '/',
      headers: { Authorization: `Bearer ${token}` },
    });
  };

  const fetchHistory = async () => {
    const api = createApiInstance();
    if (!api) return;
    try {
      const response = await api.get("/api/generations");
      setHistory(response.data);
      // Muat riwayat paling baru secara otomatis jika belum ada yang aktif
      if (response.data.length > 0 && !activeHistoryId) {
        await loadHistoryItem(response.data[0].id);
      }
    } catch (error) {
      console.error("Gagal memuat riwayat:", error);
    }
  };

  const loadHistoryItem = async (generationId) => {
    if (isLoading) return;
    setIsLoading(true);
    const api = createApiInstance();
    if (!api) return;
    try {
      const response = await api.get(`/api/generations/${generationId}`);
      setGeneratedHtml(response.data.html_code);
      setIsEditing(true);
      setActiveHistoryId(generationId);
    } catch (error) {
      toast.error("Gagal memuat detail riwayat.");
      console.error(error);
    }
    setIsLoading(false);
  };

  const deleteHistoryItem = async (generationId) => {
    setModalState({
      isOpen: true,
      title: "Hapus Riwayat?",
      message:
        "Apakah Anda yakin ingin menghapus riwayat ini? Tindakan ini tidak dapat dibatalkan.",
      onConfirm: async () => {
        const api = createApiInstance();
        if (!api) return;
        try {
          await api.delete(`/api/generations/${generationId}`);
          setHistory((prev) => prev.filter((item) => item.id !== generationId));
          if (activeHistoryId === generationId) {
            setGeneratedHtml("");
            setActiveHistoryId(null);
          }
          toast.success("Riwayat berhasil dihapus.");
        } catch (error) {
          toast.error("Gagal menghapus riwayat.");
        }
      },
    });
  };

  useEffect(() => {
    const token = localStorage.getItem("accessToken");
    if (!token) {
      navigate("/login");
    } else {
      fetchUserData(); // Panggil data user
      fetchHistory(); // Panggil riwayat
    }
  }, []);

  const handleImageUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;
    setIsLoading(true);
    const formData = new FormData();
    formData.append("image", file);
    try {
      const api = createApiInstance();
      const response = await api.post("/api/upload", formData);
      const newImageUrl = response.data.url;
      setUploadedImages((prevImages) => [...prevImages, newImageUrl]);
      setPrompt((prev) => `${prev}\n\n[Gambar ditambahkan: ${newImageUrl}]`);
    } catch (error) {
      if (error.response?.status === 401 || error.response?.status === 403)
        navigate("/login");
      else
        toast.error(
          `Gagal mengunggah gambar: ${
            error.response?.data?.error || error.message
          }`
        );
    }
    setIsLoading(false);
    event.target.value = null;
  };

  const handleGenerateOrEdit = async () => {
    if (!prompt.trim()) {
      toast.error("Prompt tidak boleh kosong!");
      return;
    }
    setIsLoading(true);
    try {
      const endpoint = isEditing ? "/api/edit" : "/api/generate";
      const payload = {
        userPrompt: prompt,
        imageUrls: uploadedImages,
        currentHtml: isEditing ? generatedHtml : null,
      };
      const api = createApiInstance();
      const response = await api.post(endpoint, payload);
      setGeneratedHtml(response.data.htmlCode);
      if (!isEditing) setIsEditing(true);
      await fetchHistory(); // Memuat ulang riwayat setelah berhasil
    } catch (error) {
      if (error.response?.status === 401 || error.response?.status === 403)
        navigate("/login");
      else
        toast.error(
          `Maaf, terjadi kesalahan: ${
            error.response?.data?.error || error.message
          }`
        );
    }
    setIsLoading(false);
    setPrompt("");
  };

  const handlePublish = async () => {
    if (!activeHistoryId) {
      return toast.error(
        "Pilih sebuah versi dari riwayat untuk dipublikasikan."
      );
    }

    // Panggil modal, bukan window.confirm
    setModalState({
      isOpen: true,
      title: "Konfirmasi Publikasi",
      message:
        "Apakah Anda yakin ingin mempublikasikan versi ini? Website Anda yang lama (jika ada) akan diganti.",
      onConfirm: () => {
        const api = createApiInstance();
        if (!api) return;

        const publishPromise = api.post(`/api/publish/${activeHistoryId}`);

        toast.promise(publishPromise, {
          loading: "Sedang mempublikasikan website Anda...",
          success: (response) => {
            setPublishedUrl(response.data.publicUrl);
            setPublishedId(activeHistoryId);
            return "Website berhasil dipublikasikan!";
          },
          error: (err) =>
            err.response?.data?.error || "Gagal mempublikasikan website.",
        });
      },
    });
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text).then(
      () => {
        toast.success("URL disalin ke clipboard!");
      },
      (err) => {
        console.error("Gagal menyalin: ", err);
        toast.error("Gagal menyalin URL.");
      }
    );
  };

  const handleUnpublish = async () => {
    setModalState({
      isOpen: true,
      title: "Hapus Publikasi?",
      message:
        "Apakah Anda yakin ingin menghapus publikasi website ini? Link akan menjadi tidak aktif.",
      onConfirm: () => {
        const api = createApiInstance();
        if (!api) return;
        const unpublishPromise = api.delete("/api/publish");
        toast.promise(unpublishPromise, {
          loading: "Sedang menghapus publikasi...",
          success: () => {
            setPublishedUrl("");
            setPublishedId(null);
            return "Publikasi berhasil dihapus.";
          },
          error: (err) =>
            err.response?.data?.error || "Gagal menghapus publikasi.",
        });
      },
    });
  };
  const handleLogout = () => {
    localStorage.removeItem("accessToken");
    navigate("/login");
  };

  const activeHistoryItem = history.find((item) => item.id === activeHistoryId);
  const displayVersionNumber = activeHistoryItem
    ? activeHistoryItem.version_number
    : null;

  return (
    <div className="flex h-screen bg-gray-100 font-sans">
      <div className="w-1/3 p-6 bg-white shadow-lg flex flex-col min-w-[400px]">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center">
            <img src={logo} alt="SisDigi UMKM Logo" className="w-24 h-24" />
            <h1 className="text-2xl font-bold ml-3 text-gray-800">SisDigi UMKM</h1>
          </div>
          <ConfirmationModal
            isOpen={modalState.isOpen}
            onClose={() => setModalState({ ...modalState, isOpen: false })}
            onConfirm={modalState.onConfirm}
            title={modalState.title}
            message={modalState.message}
          />
          <button
            onClick={handleLogout}
            className="flex items-center text-sm text-gray-500 hover:text-indigo-600 font-semibold p-2 rounded-lg hover:bg-gray-100 transition"
          >
            <LogoutIcon />
            <span className="ml-1">Logout</span>
          </button>
        </div>

        {/* --- PANEL RIWAYAT YANG DITAMBAHKAN --- */}
        <div className="mb-4">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">
            Riwayat Project
          </h2>
          <div className="space-y-2 max-h-48 overflow-y-auto bg-gray-50 p-2 rounded-lg border">
            {history.length === 0 ? (
              <p className="text-sm text-gray-400 text-center py-2">
                Belum ada riwayat.
              </p>
            ) : (
              history.map((item) => (
                <div
                  key={item.id}
                  onClick={() => loadHistoryItem(item.id)}
                  className={`flex items-center justify-between p-2 rounded-md cursor-pointer transition ${
                    activeHistoryId === item.id
                      ? "bg-indigo-100 ring-2 ring-indigo-400"
                      : "hover:bg-gray-200"
                  }`}
                >
                  <div className="text-sm">
                    <p className="font-semibold text-gray-800">
                      Versi #{item.version_number}
                    </p>
                    <p className="text-gray-500">
                      {new Date(item.created_at).toLocaleString("id-ID")}
                    </p>
                  </div>
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      deleteHistoryItem(item.id);
                    }}
                    className="p-2 rounded-full text-gray-400 hover:bg-red-100 hover:text-red-600"
                  >
                    <TrashIcon />
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* --- PANEL PUBLIKASI DINAMIS --- */}
        <div className="mt-4 border-t pt-4">
          <h2 className="text-lg font-semibold text-gray-700 mb-2">
            Publikasi
          </h2>
          {publishedUrl ? (
            <div className="text-sm bg-green-50 p-3 rounded-lg border border-green-200">
              <p className="font-semibold text-green-800">
                Website Anda sudah live!
              </p>
              <a
                href={publishedUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-blue-600 hover:underline break-all"
              >
                {publishedUrl}
              </a>
              <button
                onClick={handleUnpublish}
                className="w-full mt-3 bg-red-600 text-white font-bold py-2 rounded-lg hover:bg-red-700 transition"
              >
                Hapus Publikasi
              </button>
            </div>
          ) : (
            <div>
              <p className="text-sm text-gray-500 mb-2">
                Pilih salah satu versi dari riwayat di atas, lalu klik tombol
                publish.
              </p>
              <button
                onClick={handlePublish}
                disabled={!activeHistoryId || isLoading}
                className="w-full bg-green-600 text-white font-bold py-3 rounded-lg hover:bg-green-700 transition disabled:bg-gray-400"
              >
                Publish Versi #{displayVersionNumber}
              </button>
            </div>
          )}
        </div>

        <div className="flex-grow flex flex-col border-t pt-4 overflow-y-auto">
          <label htmlFor="prompt" className="text-gray-600 font-semibold mb-2">
            Ceritakan bisnis Anda atau apa yang ingin diubah:
          </label>
          <textarea
            id="prompt"
            className="w-full p-3 border rounded-lg text-gray-700 focus:ring-2 focus:ring-indigo-400 transition"
            rows="8"
            placeholder="Contoh: Buatkan website untuk 'Kopi Senja'..."
            value={prompt}
            onChange={(e) => setPrompt(e.target.value)}
            disabled={isLoading}
          />
          <div className="mt-4">
            <h3 className="font-semibold text-gray-600 mb-2">
              Gambar Terunggah:
            </h3>
            <div className="space-y-2 max-h-48 overflow-y-auto bg-gray-50 p-2 rounded-lg border">
              {uploadedImages.length === 0 ? (
                <p className="text-sm text-gray-400 text-center py-2">
                  Belum ada gambar.
                </p>
              ) : (
                uploadedImages.map((url, index) => (
                  <div
                    key={index}
                    className="flex items-center text-xs p-1 bg-white rounded shadow-sm"
                  >
                    <img
                      src={url}
                      alt={`upload-${index}`}
                      className="w-8 h-8 object-cover rounded mr-2"
                    />
                    <span className="truncate flex-1 text-gray-500">
                      {url.substring(url.lastIndexOf("/") + 1)}
                    </span>
                    <button
                      onClick={() => copyToClipboard(url)}
                      className="ml-2 p-1 text-gray-400 hover:text-indigo-500"
                      title="Salin URL Gambar"
                    >
                      <CopyIcon />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        <div className="mt-6 flex space-x-2 pt-4 border-t">
          <input
            type="file"
            ref={fileInputRef}
            onChange={handleImageUpload}
            className="hidden"
            accept="image/png, image/jpeg, image/webp"
          />
          <button
            className="flex-1 bg-gray-200 text-gray-700 px-4 py-3 rounded-lg font-semibold hover:bg-gray-300 transition flex items-center justify-center disabled:opacity-50"
            onClick={() => fileInputRef.current.click()}
            disabled={isLoading}
          >
            <UploadIcon /> <span className="ml-2">Upload Gambar</span>
          </button>
          <button
            className="flex-1 bg-indigo-600 text-white px-4 py-3 rounded-lg font-bold hover:bg-indigo-700 transition disabled:bg-indigo-400 flex items-center justify-center"
            onClick={handleGenerateOrEdit}
            disabled={isLoading}
          >
            {isLoading && (
              <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white mr-3"></div>
            )}
            {isLoading
              ? "AI sedang berpikir..."
              : isEditing
              ? "Terapkan Perubahan"
              : "Buatkan Website Saya!"}
          </button>
        </div>
      </div>

      <div className="w-2/3 p-4 flex-grow relative">
        <div className="w-full h-full bg-white rounded-xl shadow-inner overflow-hidden">
          {generatedHtml && !isLoading ? (
            <iframe
              srcDoc={generatedHtml}
              title="Generated Website Preview"
              className="w-full h-full border-0"
              sandbox="allow-scripts allow-same-origin"
            />
          ) : (
            // ... Konten placeholder ...
            <div className="w-full h-full flex items-center justify-center bg-gray-50">
              <p className="text-gray-400">
                {!isLoading
                  ? "Preview website Anda akan muncul di sini..."
                  : ""}
              </p>
            </div>
          )}
        </div>
        {isLoading && (
          // ... Indikator loading ...
          <div className="absolute inset-4 flex items-center justify-center bg-white bg-opacity-75 rounded-xl">
            <div className="text-center">
              <div className="animate-spin rounded-full h-12 w-12 border-b-4 border-indigo-600 mx-auto"></div>
              <p className="mt-4 text-lg font-semibold text-indigo-800">
                AI sedang memproses permintaan Anda...
              </p>
              <p className="text-sm text-gray-600">
                Ini mungkin memerlukan waktu beberapa saat.
              </p>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
