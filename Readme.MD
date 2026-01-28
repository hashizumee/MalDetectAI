# 🛡️ MalDetect AI

Sistem deteksi malware yang canggih menggunakan Machine Learning (PyTorch) dan YARA rules untuk menganalisis file executable dan binary.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![PyTorch](https://img.shields.io/badge/PyTorch-2.1+-red.svg)
![YARA](https://img.shields.io/badge/YARA-4.3+-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🌟 Fitur Utama

### 1. **Machine Learning Detection**
- Deep Neural Network dengan 5 layers
- 100+ features extraction otomatis
- Batch Normalization & Dropout untuk akurasi tinggi
- Real-time prediction dengan confidence score

### 2. **YARA Rule Engine**
- Pattern matching untuk deteksi malware
- Multiple rule categories:
  - Suspicious Executable
  - Ransomware Indicators
  - Keylogger Behavior
  - Network Communication
- Support untuk custom rules

### 3. **Static Analysis**
- PE file parsing lengkap
- Entropy calculation
- Hash generation (MD5, SHA256)
- Byte frequency analysis
- Section characteristics analysis

### 4. **Interactive Dashboard**
- Real-time visualization
- Scan history tracking
- Export hasil ke JSON
- Multi-tab interface

## 🚀 Instalasi

### Prerequisites
- Python 3.8 atau lebih tinggi
- pip package manager

### Langkah Instalasi

1. **Clone atau download project ini**
```bash
git clone <repository-url>
cd maldetect-ai
```

2. **Install dependencies**
```bash
pip install -r requirements.txt
```

3. **Jalankan aplikasi**
```bash
streamlit run maldetect_app.py
```

4. **Akses aplikasi**
Buka browser dan kunjungi: `http://localhost:8501`

## 📖 Cara Menggunakan

### 1. Upload File
- Klik tab "🔍 Scan File"
- Upload file executable (.exe, .dll, .sys) atau binary (.bin, .dat)
- Maksimal ukuran file: 100MB

### 2. Konfigurasi Scanning
Di sidebar, atur:
- **Threshold Deteksi**: Nilai ambang batas (default: 0.5)
- **YARA Scan**: Aktifkan/nonaktifkan pattern matching

### 3. Analisis Hasil
Setelah scanning selesai, Anda akan melihat:
- **Status**: Malware terdeteksi atau file aman
- **Skor ML**: Probability malware (0-100%)
- **YARA Matches**: Pattern mencurigakan yang terdeteksi
- **Hash Information**: MD5 dan SHA256
- **Feature Analysis**: Visualisasi fitur

### 4. Review Detil
- **Entropy**: Nilai tinggi (>7) mengindikasikan kompresi/enkripsi
- **YARA Rules**: Pattern spesifik yang match
- **Feature Distribution**: Analisis karakteristik file

## 🔬 Arsitektur Sistem

### Neural Network Architecture
```
Input Layer (100 features)
    ↓
Dense Layer (256) + BatchNorm + Dropout(0.3)
    ↓
Dense Layer (128) + BatchNorm + Dropout(0.3)
    ↓
Dense Layer (64) + BatchNorm + Dropout(0.2)
    ↓
Dense Layer (32) + BatchNorm
    ↓
Output Layer (1) + Sigmoid
```

### Feature Extraction Pipeline
1. **Hash-based Features**: MD5, SHA256
2. **Byte Analysis**: Frequency distribution, entropy
3. **PE Features**: Sections, headers, imports
4. **Statistical Features**: Mean, standard deviation
5. **Pattern Features**: Null bytes, printable characters

### YARA Rules Categories
1. **Suspicious Executable**: CMD, PowerShell, Registry manipulation
2. **Ransomware Indicators**: Encryption, Bitcoin, ransom notes
3. **Keylogger Behavior**: Keyboard monitoring APIs
4. **Network Communication**: Sockets, URLs, IP patterns

## 📊 Interpretasi Hasil

### Skor ML
- **0-30%**: Risiko rendah (kemungkinan besar aman)
- **30-70%**: Risiko sedang (perlu investigasi lebih lanjut)
- **70-100%**: Risiko tinggi (kemungkinan besar malware)

### Entropy
- **< 6.0**: File tidak terkompresi
- **6.0-7.0**: Kompresi normal
- **> 7.0**: Enkripsi atau packing (suspicious)

### YARA Matches
- **0 matches**: Tidak ada pattern mencurigakan
- **1-2 matches**: Perhatikan dengan hati-hati
- **3+ matches**: Sangat mencurigakan

## 🎯 Use Cases

### 1. Security Analysis
- Analisis malware untuk tim keamanan
- Incident response investigation
- Threat hunting

### 2. File Verification
- Verifikasi file sebelum eksekusi
- Check integritas software
- Validasi download

### 3. Research & Education
- Studi malware analysis
- Machine learning untuk cybersecurity
- Pattern recognition research

## ⚙️ Konfigurasi Lanjutan

### Custom YARA Rules
Edit bagian `YARA_RULES` di `maldetect_app.py`:

```python
YARA_RULES = """
rule Custom_Rule
{
    meta:
        description = "Your custom rule"
    
    strings:
        $pattern1 = "suspicious_string"
    
    condition:
        $pattern1
}
"""
```

### Model Training
Untuk melatih model dengan dataset Anda:

```python
# Siapkan dataset
X_train, y_train = load_malware_dataset()

# Training
model = MalwareDetector()
criterion = nn.BCELoss()
optimizer = torch.optim.Adam(model.parameters())

for epoch in range(epochs):
    optimizer.zero_grad()
    outputs = model(X_train)
    loss = criterion(outputs, y_train)
    loss.backward()
    optimizer.step()

# Save model
torch.save(model.state_dict(), 'malware_detector.pth')
```

## 📈 Performance

### Feature Extraction
- **Speed**: ~0.1-0.5 detik per file
- **Accuracy**: 100+ features extracted
- **Support**: PE files dan binary generik

### ML Prediction
- **Latency**: < 10ms per prediksi
- **Model Size**: ~2MB
- **Inference**: CPU-based (GPU optional)

### YARA Scanning
- **Speed**: ~0.05-0.2 detik per file
- **Rules**: 4 categories built-in
- **Extensible**: Custom rules supported

## 🛠️ Teknologi

| Komponen | Teknologi | Versi |
|----------|-----------|-------|
| Deep Learning | PyTorch | 2.1+ |
| Pattern Matching | YARA | 4.3+ |
| PE Parser | pefile | 2023.2.7 |
| Web Framework | Streamlit | 1.31+ |
| Visualization | Plotly | 5.18+ |
| Data Processing | NumPy, Pandas | Latest |

## ⚠️ Disclaimer

**PENTING**: MalDetect AI adalah tool untuk tujuan edukasi dan penelitian.

- ✅ Gunakan untuk analisis keamanan yang sah
- ✅ Verifikasi hasil dengan tools profesional lainnya
- ❌ Jangan gunakan sebagai satu-satunya defense
- ❌ Tidak menggantikan antivirus komersial

Hasil deteksi harus diverifikasi dan dikonfirmasi dengan:
- Antivirus engine multiple
- Sandbox analysis (Cuckoo, ANY.RUN)
- Manual reverse engineering
- Threat intelligence platforms

## 🔐 Security Best Practices

1. **Isolasi**: Jalankan scanning di environment terisolasi
2. **Validation**: Selalu validasi file dari sumber terpercaya
3. **Updates**: Update YARA rules secara berkala
4. **Backup**: Backup file penting sebelum scanning
5. **Logs**: Simpan scan history untuk audit trail

## 📝 Contoh Output

```
🛡️ MalDetect AI - Hasil Scan

File: suspicious.exe
Ukuran: 245 KB
MD5: 5d41402abc4b2a76b9719d911017c592
SHA256: 2c26b46b68ffc68ff99b453c1d30413413422d706...

⚠️ MALWARE TERDETEKSI!
Tingkat Ancaman: TINGGI

Skor ML: 87.5%
YARA Matches: 3
- Suspicious_Executable
- Network_Communication  
- Ransomware_Indicators

Entropy: 7.42 (High - Potentially packed/encrypted)

Rekomendasi:
🚫 JANGAN jalankan file ini
🗑️ Hapus dari sistem
🔒 Scan sistem dengan antivirus
```

## 🤝 Contributing

Kontribusi sangat diterima! Silakan:
1. Fork repository
2. Buat feature branch
3. Commit changes
4. Push ke branch
5. Buat Pull Request

## 📄 License

Project ini dilisensikan di bawah MIT License.

## 👨‍💻 Author

Dibuat dengan ❤️ menggunakan Python, PyTorch, dan YARA

---

## 🔗 Resources

- [PyTorch Documentation](https://pytorch.org/docs/)
- [YARA Documentation](https://yara.readthedocs.io/)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Malware Analysis Resources](https://github.com/rshipp/awesome-malware-analysis)

---

**⭐ Jika project ini membantu, berikan star di GitHub!**