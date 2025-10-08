// --- Impor semua library yang dibutuhkan ---
require("dotenv").config(); // Pastikan ini di paling atas untuk memuat .env
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2/promise");
const jwt = require("jsonwebtoken");
const {
  BedrockRuntimeClient,
  InvokeModelCommand,
} = require("@aws-sdk/client-bedrock-runtime");
const {
  S3Client,
  PutObjectCommand,
  DeleteObjectCommand,
} = require("@aws-sdk/client-s3");
const multer = require("multer");

// =================================================================
// --- KONFIGURASI UTAMA & INISIALISASI ---
// =================================================================
const app = express();
const PORT = process.env.PORT || 3001;
const REGION = "us-west-2"; // Pastikan ini sesuai dengan region AWS Anda

// Konfigurasi Nama Bucket S3 (pastikan namanya unik secara global)
const ASSET_BUCKET_NAME = "aset-backend-umkm-generator";
const HOSTING_BUCKET_NAME = "published-website-umkm";

// Koneksi Database MySQL (menggunakan pool untuk efisiensi)
const dbPool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  waitForConnections: true, // Menunggu jika semua koneksi sedang dipakai
  connectionLimit: 10, // Batas maksimal koneksi dalam pool
  queueLimit: 0, // Tidak ada batasan antrian
});

// Inisialisasi AWS Clients dengan region yang sudah ditentukan
const bedrockClient = new BedrockRuntimeClient({ region: REGION });
const s3Client = new S3Client({ region: REGION });

// Konfigurasi Multer untuk menangani upload file di memori
// File akan disimpan di RAM sementara sebelum diupload ke S3
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // Batas ukuran file 5MB
});

// =================================================================
// --- MIDDLEWARE GLOBAL ---
// =================================================================
app.use(cors()); // Mengizinkan request dari frontend (beda port/domain)
app.use(express.json({ limit: "10mb" })); // Mengizinkan request body JSON, dengan batas 10MB

// =================================================================
// --- MIDDLEWARE AUTENTIKASI ---
// Digunakan untuk melindungi rute yang memerlukan token JWT
// =================================================================
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers["authorization"];
  // Format: "Bearer TOKEN_ANDA"
  const token = authHeader && authHeader.split(" ")[1];

  if (token == null) {
    // Jika tidak ada token, kirim status 401 Unauthorized
    return res
      .status(401)
      .json({ message: "Akses ditolak: Token tidak ditemukan." });
  }

  // Verifikasi token menggunakan JWT_SECRET dari environment variables
  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      // Jika token tidak valid atau kadaluarsa, kirim status 403 Forbidden
      return res
        .status(403)
        .json({ message: "Akses ditolak: Token tidak valid." });
    }
    req.user = user; // Simpan payload user ke objek request
    next(); // Lanjutkan ke handler rute berikutnya
  });
};

// =================================================================
// --- RUTE PUBLIK (TIDAK MEMERLUKAN AUTENTIKASI) ---
// =================================================================

// Rute untuk registrasi pengguna baru
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;
    // Validasi input
    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ message: "Nama, email, dan password harus diisi." });
    }

    // Cek apakah email sudah terdaftar di database
    const [existingUsers] = await dbPool.query(
      "SELECT id FROM users WHERE email = ?",
      [email]
    );
    if (existingUsers.length > 0) {
      return res.status(409).json({ message: "Email sudah terdaftar." }); // 409 Conflict
    }

    // Simpan user baru ke database
    // Catatan: Dalam aplikasi nyata, password harus di-hash (misal dengan bcrypt)
    const [result] = await dbPool.query(
      "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
      [name, email, password]
    );

    console.log(`User baru terdaftar: ${email}`);
    res
      .status(201)
      .json({ message: "Registrasi berhasil!", userId: result.insertId }); // 201 Created
  } catch (error) {
    console.error("Error di /api/auth/register:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// Rute untuk login pengguna
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    // Validasi input
    if (!email || !password) {
      return res
        .status(400)
        .json({ message: "Email dan password harus diisi." });
    }

    // Cari user berdasarkan email di database
    const [users] = await dbPool.query("SELECT * FROM users WHERE email = ?", [
      email,
    ]);
    if (users.length === 0) {
      return res.status(401).json({ message: "Email atau password salah." });
    }

    const user = users[0];

    // Bandingkan password (di aplikasi nyata, bandingkan dengan hash password)
    const isMatch = password === user.password; // Harusnya bcrypt.compare(password, user.passwordHash)
    if (!isMatch) {
      return res.status(401).json({ message: "Email atau password salah." });
    }

    // Buat JWT Token
    const accessToken = jwt.sign(
      { id: user.id, name: user.name, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "1d" } // Token berlaku 1 hari
    );

    console.log(`User login berhasil: ${email}`);
    res.json({ accessToken });
  } catch (error) {
    console.error("Error di /api/auth/login:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

app.get('/health', (req, res) => {
    // Cukup kirim respons 200 OK untuk memberitahu Load Balancer bahwa aplikasi berjalan
    res.status(200).send('Ok');
});


// =================================================================
// --- RUTE YANG MEMERLUKAN AUTENTIKASI (MIDDLEWARE `authenticateToken` DIAPLIKASIKAN) ---
// =================================================================

// Endpoint untuk mendapatkan data pengguna yang sedang login
// Pastikan ini di atas `app.use(authenticateToken);` jika Anda ingin hanya rute ini yang dilindungi
// atau di bawah jika ingin semua rute di bawah dilindungi.
app.get("/api/auth/me", authenticateToken, async (req, res) => {
  try {
    // req.user berasal dari payload JWT yang sudah diverifikasi
    const [users] = await dbPool.query(
      "SELECT id, name, email, published_url, published_generation_id FROM users WHERE id = ?",
      [req.user.id]
    );
    if (users.length === 0) {
      return res.status(404).json({ message: "User tidak ditemukan." });
    }
    res.json(users[0]);
  } catch (error) {
    console.error("Error di /api/auth/me:", error);
    res.status(500).json({ message: "Terjadi kesalahan pada server." });
  }
});

// Terapkan middleware autentikasi untuk semua rute di bawah ini
app.use(authenticateToken);

// Endpoint untuk mengunggah gambar ke S3
app.post("/api/upload", upload.single("image"), async (req, res) => {
  // Cek jika tidak ada file yang di-upload
  if (!req.file) {
    return res.status(400).json({ error: "Tidak ada file yang diunggah." });
  }

  const file = req.file;
  // Membuat nama file unik untuk mencegah konflik
  const fileName = `${Date.now()}-${file.originalname.replace(/\s/g, "_")}`;

  // Menyiapkan parameter untuk diunggah ke S3
  const uploadParams = {
    Bucket: ASSET_BUCKET_NAME, // Menggunakan bucket untuk aset
    Key: fileName,
    Body: file.buffer,
    ContentType: file.mimetype,
  };

  try {
    // Mengirim perintah upload ke S3
    await s3Client.send(new PutObjectCommand(uploadParams));
    // Membuat URL publik secara manual agar bisa diakses
    const imageUrl = `https://${ASSET_BUCKET_NAME}.s3.${REGION}.amazonaws.com/${fileName}`;

    console.log(
      `[${new Date().toLocaleTimeString()}] Upload berhasil. URL: ${imageUrl}`
    );
    res.json({ url: imageUrl });
  } catch (error) {
    console.error("Error saat upload ke S3:", error);
    res.status(500).json({ error: "Gagal mengunggah file ke S3." });
  }
});

// Endpoint untuk generate website baru menggunakan Bedrock
app.post("/api/generate", async (req, res) => {
  try {
    const { userPrompt, imageUrls } = req.body;
    const userId = req.user.id; // Diperoleh dari JWT payload

    if (!userPrompt) {
      return res.status(400).json({ error: "Prompt tidak boleh kosong" });
    }

    console.log(
      `[${new Date().toLocaleTimeString()}] Menerima permintaan /api/generate dari user ID: ${userId}`
    );

    const systemPrompt = createSystemPrompt(false); // Untuk generate baru
    const userMessages = [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: `Deskripsi bisnis: "${userPrompt}".\n\nDaftar URL gambar: ${
              imageUrls.length > 0 ? imageUrls.join(", ") : "Tidak ada"
            }`,
          },
        ],
      },
    ];

    const htmlCode = await invokeBedrock(systemPrompt, userMessages);

    // Simpan hasil generasi ke database
    await dbPool.query(
      "INSERT INTO generations (user_id, html_code) VALUES (?, ?)",
      [userId, htmlCode]
    );

    console.log(`Riwayat generate disimpan untuk user ID: ${userId}`);

    res.json({ htmlCode });
  } catch (error) {
    console.error("Error di /api/generate:", error);
    res.status(500).json({ error: "Gagal menghasilkan website." });
  }
});

// Endpoint untuk mengedit website yang sudah ada
app.post("/api/edit", async (req, res) => {
  try {
    const { userPrompt, imageUrls, currentHtml } = req.body;
    const userId = req.user.id;

    if (!userPrompt || !currentHtml) {
      return res
        .status(400)
        .json({ error: "Data tidak lengkap untuk mengedit." });
    }

    console.log(
      `[${new Date().toLocaleTimeString()}] Menerima permintaan /api/edit dari user ID: ${userId}`
    );

    const systemPrompt = createSystemPrompt(true); // Untuk mode edit
    const userMessages = [
      {
        role: "user",
        content: [
          {
            type: "text",
            text: `PERMINTAAN EDIT: "${userPrompt}"\n\nDaftar URL gambar yang tersedia: ${
              imageUrls.length > 0 ? imageUrls.join(", ") : "Tidak ada"
            }\n\nKODE HTML SAAT INI UNTUK DIEDIT:\n\`\`\`html\n${currentHtml}\n\`\`\``,
          },
        ],
      },
    ];

    const htmlCode = await invokeBedrock(systemPrompt, userMessages);

    // Simpan hasil editan sebagai generasi baru di database
    await dbPool.query(
      "INSERT INTO generations (user_id, html_code) VALUES (?, ?)",
      [userId, htmlCode]
    );

    console.log(`Riwayat edit disimpan untuk user ID: ${userId}`);

    res.json({ htmlCode });
  } catch (error) {
    console.error("Error di /api/edit:", error);
    res.status(500).json({ error: "Gagal mengedit website." });
  }
});

// Endpoint untuk mengambil daftar riwayat generasi website pengguna
app.get("/api/generations", async (req, res) => {
  try {
    const userId = req.user.id;

    // Ambil semua riwayat untuk user ini, diurutkan dari yang PALING LAMA ke PALING BARU
    const [historyFromDb] = await dbPool.query(
      "SELECT id, LEFT(html_code, 100) as preview, created_at FROM generations WHERE user_id = ? ORDER BY created_at ASC",
      [userId]
    );

    // --- LOGIKA UNTUK MEMBUAT NOMOR VERSI ---
    // Kita akan menambahkan nomor versi secara manual di sini, karena urutan di database bisa berubah
    const historyWithVersion = historyFromDb.map((item, index) => ({
      ...item,
      version_number: index + 1, // Item pertama (paling lama) akan jadi Versi #1, dst.
    }));

    // Balik urutan array agar yang terbaru muncul di atas saat ditampilkan di frontend
    const finalHistory = historyWithVersion.reverse();

    res.json(finalHistory);
  } catch (error) {
    console.error("Error di /api/generations:", error);
    res.status(500).json({ error: "Gagal mengambil riwayat." });
  }
});

// Endpoint untuk mengambil konten HTML dari satu riwayat berdasarkan ID
app.get("/api/generations/:id", async (req, res) => {
  try {
    const userId = req.user.id;
    const generationId = req.params.id;

    // Security Check: Pastikan user hanya bisa mengambil riwayat miliknya sendiri
    const [rows] = await dbPool.query(
      "SELECT html_code FROM generations WHERE id = ? AND user_id = ?",
      [generationId, userId]
    );

    if (rows.length === 0) {
      return res.status(404).json({
        error: "Riwayat tidak ditemukan atau Anda tidak memiliki akses.",
      });
    }

    res.json({ html_code: rows[0].html_code });
  } catch (error) {
    console.error("Error di /api/generations/:id :", error);
    res.status(500).json({ error: "Gagal mengambil detail riwayat." });
  }
});

// Endpoint untuk menghapus satu riwayat generasi website
app.delete("/api/generations/:id", async (req, res) => {
  try {
    const userId = req.user.id;
    const generationId = req.params.id;

    // Security Check: Pastikan user hanya bisa menghapus riwayat miliknya sendiri
    const [result] = await dbPool.query(
      "DELETE FROM generations WHERE id = ? AND user_id = ?",
      [generationId, userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({
        error: "Riwayat tidak ditemukan atau Anda tidak memiliki akses.",
      });
    }

    console.log(
      `Riwayat ID ${generationId} untuk user ID ${userId} berhasil dihapus.`
    );
    res.status(200).json({ message: "Riwayat berhasil dihapus." });
  } catch (error) {
    console.error("Error di /api/generations/:id (DELETE):", error);
    res.status(500).json({ error: "Gagal menghapus riwayat." });
  }
});

// Endpoint untuk mempublikasikan website yang sudah digenerate ke S3 Static Website Hosting
app.post("/api/publish/:id", async (req, res) => {
  try {
    const userId = req.user.id;
    const generationId = req.params.id;

    // Cek apakah user sudah punya link yang terpublikasi sebelumnya
    const [users] = await dbPool.query(
      "SELECT published_url FROM users WHERE id = ?",
      [userId]
    );
    if (users[0].published_url) {
      return res.status(409).json({
        error:
          "Anda sudah memiliki website yang terpublikasi. Hapus terlebih dahulu untuk mempublikasikan versi baru.",
      });
    }

    // Ambil HTML dari database berdasarkan generationId dan userId (security check)
    const [rows] = await dbPool.query(
      "SELECT html_code FROM generations WHERE id = ? AND user_id = ?",
      [generationId, userId]
    );
    if (rows.length === 0) {
      return res.status(404).json({
        error: "Riwayat tidak ditemukan atau Anda tidak memiliki akses.",
      });
    }

    const htmlCode = rows[0].html_code;

    // Upload file HTML ke S3 Hosting Bucket. Key unik per user.
    const uploadParams = {
      Bucket: HOSTING_BUCKET_NAME,
      Key: `${userId}/index.html`, // Contoh: 1/index.html
      Body: htmlCode,
      ContentType: "text/html",
    };
    await s3Client.send(new PutObjectCommand(uploadParams));

    // Buat URL publik untuk website yang di-host di S3
    const publicUrl = `http://${HOSTING_BUCKET_NAME}.s3-website.${REGION}.amazonaws.com/${userId}/`;

    // Simpan URL publik dan ID generasi ke tabel user
    await dbPool.query(
      "UPDATE users SET published_url = ?, published_generation_id = ? WHERE id = ?",
      [publicUrl, generationId, userId]
    );

    console.log(
      `Website untuk user ${userId} berhasil dipublikasikan di ${publicUrl}`
    );
    res.json({ publicUrl });
  } catch (error) {
    console.error("Error di /api/publish:", error);
    res.status(500).json({ error: "Gagal mempublikasikan website." });
  }
});

// Endpoint untuk menghapus publikasi website (unpublish)
app.delete("/api/publish", async (req, res) => {
  try {
    const userId = req.user.id;

    // Hapus file HTML dari S3 Hosting Bucket
    const deleteParams = {
      Bucket: HOSTING_BUCKET_NAME,
      Key: `${userId}/index.html`,
    };
    await s3Client.send(new DeleteObjectCommand(deleteParams));

    // Hapus URL publik dan ID generasi dari tabel user di database
    await dbPool.query(
      "UPDATE users SET published_url = NULL, published_generation_id = NULL WHERE id = ?",
      [userId]
    );

    console.log(`Publikasi untuk user ${userId} berhasil dihapus.`);
    res.status(200).json({ message: "Publikasi berhasil dihapus." });
  } catch (error) {
    console.error("Error di /api/publish (DELETE):", error);
    res.status(500).json({ error: "Gagal menghapus publikasi." });
  }
});

// =================================================================
// --- FUNGSI UTAMA UNTUK MENGHUBUNGI AWS BEDROCK ---
// =================================================================
async function invokeBedrock(systemPrompt, userMessages) {
  const modelId = "anthropic.claude-3-5-sonnet-20240620-v1:0"; // Model yang digunakan

  const payload = {
    anthropic_version: "bedrock-2023-05-31",
    max_tokens: 4096, // Jumlah maksimal token yang dihasilkan AI
    temperature: 0.7, // Tingkat kreativitas (0.0 - 1.0)
    system: systemPrompt, // Instruksi sistem
    messages: userMessages, // Pesan dari pengguna
  };

  const command = new InvokeModelCommand({
    modelId,
    contentType: "application/json",
    body: JSON.stringify(payload),
  });

  console.log(
    `[${new Date().toLocaleTimeString()}] Mengirim permintaan ke Bedrock...`
  );
  const apiResponse = await bedrockClient.send(command);
  console.log(
    `[${new Date().toLocaleTimeString()}] Menerima respons dari Bedrock.`
  );

  const decodedBody = new TextDecoder().decode(apiResponse.body);
  const responseBody = JSON.parse(decodedBody);

  if (responseBody.content && responseBody.content[0].type === "text") {
    let rawResponse = responseBody.content[0].text;

    // Regex untuk membersihkan respons AI dan mengambil hanya blok kode HTML
    const codeBlockRegex = /```(?:html)?\s*([\s\S]*?)\s*```/;
    const match = rawResponse.match(codeBlockRegex);

    let htmlCode = match ? match[1] : rawResponse;

    // Membersihkan teks penjelasan di awal jika tidak ada blok kode dan DocType tidak di awal
    const docTypeIndex = htmlCode.indexOf("<!DOCTYPE html>");
    if (docTypeIndex > 0) {
      htmlCode = htmlCode.substring(docTypeIndex);
    }

    return htmlCode.trim(); // Mengembalikan kode HTML yang sudah bersih
  } else {
    throw new Error("Format respons dari Bedrock tidak terduga.");
  }
}

// =================================================================
// --- FUNGSI UNTUK MEMBUAT SYSTEM PROMPT YANG DETAIL ---
// =================================================================
function createSystemPrompt(isEdit = false) {
  const baseInstructions = `Anda adalah seorang desainer dan developer web AI terkemuka yang ahli dalam menciptakan website satu halaman yang indah dan modern untuk UMKM Indonesia menggunakan HTML dan TailwindCSS.
    
Aturan Utama:
1.  **PENGGUNAAN GAMBAR:** Ini adalah aturan paling penting. Jika pengguna memberikan URL gambar, **WAJIB** gunakan URL tersebut. **JANGAN PERNAH** menggunakan URL gambar placeholder (seperti dari placehold.co atau unsplash) jika URL yang relevan sudah disediakan.
2.  **DESAIN MODERN:** Buat desain yang profesional dan tidak kaku. Gunakan layout yang menarik, bayangan (shadows) yang halus, sudut yang membulat (rounded corners), dan jika cocok, gunakan gradient warna yang subtle.
3.  **TIPOGRAFI:** Selalu impor dan gunakan font yang bagus dari Google Fonts, seperti 'Poppins' atau 'Inter', di dalam tag <head>.
4.  **INTERAKTIVITAS:** Tambahkan transisi (transition) pada tombol dan link saat di-hover. Jika memungkinkan, tambahkan animasi halus saat elemen muncul ketika di-scroll.
5.  **KODE BERSIH:** Hasil harus berupa satu file HTML lengkap (termasuk <!DOCTYPE html>, <html>, <head>, dan <body>).
6.  **FUNGSIONALITAS:** **WAJIB** sertakan blok <script> berikut tepat sebelum tag penutup </body> untuk memastikan navigasi di dalam halaman berjalan mulus.
    <script>
        document.querySelectorAll('a[href^="#"]').forEach(anchor => {
            anchor.addEventListener('click', function (e) {
                e.preventDefault();
                const targetId = this.getAttribute('href');
                const targetElement = document.querySelector(targetId);
                if (targetElement) {
                    targetElement.scrollIntoView({ behavior: 'smooth' });
                }
            });
        });
    <\/script>
7.  **OUTPUT FINAL:** Hasil akhir **HANYA** berupa blok kode HTML saja. JANGAN tambahkan kalimat penjelasan atau komentar apa pun di luar blok kode HTML.`;

  if (isEdit) {
    return `Anda adalah seorang developer web AI yang ahli. Tugas Anda adalah memodifikasi kode HTML yang ada berdasarkan permintaan pengguna. Patuhi semua Aturan Utama berikut:\n\n${baseInstructions}`;
  }
  return baseInstructions;
}

// =================================================================
// --- MENJALANKAN SERVER ---
// =================================================================
app.listen(PORT, () => {
  console.log(`Server Backend berjalan di http://localhost:${PORT}`);
});
