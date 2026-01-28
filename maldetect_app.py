import streamlit as st
import torch
import torch.nn as nn
import numpy as np
import pandas as pd
import hashlib
import yara
import pefile
import io
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime
import json

# Konfigurasi halaman
st.set_page_config(
    page_title="MalDetect AI",
    page_icon="🛡️",
    layout="wide"
)

# Model Neural Network untuk Deteksi Malware
class MalwareDetector(nn.Module):
    def __init__(self, input_size=100):
        super(MalwareDetector, self).__init__()
        self.fc1 = nn.Linear(input_size, 256)
        self.bn1 = nn.BatchNorm1d(256)
        self.dropout1 = nn.Dropout(0.3)
        
        self.fc2 = nn.Linear(256, 128)
        self.bn2 = nn.BatchNorm1d(128)
        self.dropout2 = nn.Dropout(0.3)
        
        self.fc3 = nn.Linear(128, 64)
        self.bn3 = nn.BatchNorm1d(64)
        self.dropout3 = nn.Dropout(0.2)
        
        self.fc4 = nn.Linear(64, 32)
        self.bn4 = nn.BatchNorm1d(32)
        
        self.fc5 = nn.Linear(32, 1)
        self.relu = nn.ReLU()
        self.sigmoid = nn.Sigmoid()
        
    def forward(self, x):
        x = self.relu(self.bn1(self.fc1(x)))
        x = self.dropout1(x)
        x = self.relu(self.bn2(self.fc2(x)))
        x = self.dropout2(x)
        x = self.relu(self.bn3(self.fc3(x)))
        x = self.dropout3(x)
        x = self.relu(self.bn4(self.fc4(x)))
        x = self.sigmoid(self.fc5(x))
        return x

# Fungsi untuk ekstraksi fitur dari file
def extract_features(file_bytes):
    """Ekstraksi fitur dari file executable"""
    features = []
    
    try:
        # Hash-based features
        md5_hash = hashlib.md5(file_bytes).hexdigest()
        sha256_hash = hashlib.sha256(file_bytes).hexdigest()
        
        # Byte frequency analysis
        byte_freq = np.bincount(np.frombuffer(file_bytes[:10000], dtype=np.uint8), minlength=256)
        byte_freq_normalized = byte_freq / (len(file_bytes[:10000]) + 1)
        
        # Entropy calculation
        entropy = -np.sum(byte_freq_normalized * np.log2(byte_freq_normalized + 1e-10))
        
        # File size
        file_size = len(file_bytes)
        
        # PE file analysis (jika applicable)
        pe_features = extract_pe_features(file_bytes)
        
        # Byte patterns
        null_bytes = file_bytes.count(b'\x00')
        printable_chars = sum(1 for b in file_bytes[:1000] if 32 <= b <= 126)
        
        # Statistical features
        byte_array = np.frombuffer(file_bytes[:10000], dtype=np.uint8)
        mean_byte = np.mean(byte_array)
        std_byte = np.std(byte_array)
        
        # Compile features
        features = [
            entropy,
            file_size / 1000000,  # Normalize
            null_bytes / (file_size + 1),
            printable_chars / 1000,
            mean_byte / 255,
            std_byte / 255,
        ]
        
        # Add PE features
        features.extend(pe_features)
        
        # Add byte frequency (top 20 most common)
        top_bytes = np.sort(byte_freq_normalized)[-20:]
        features.extend(top_bytes.tolist())
        
        # Pad or truncate to fixed size
        while len(features) < 100:
            features.append(0.0)
        features = features[:100]
        
        return np.array(features, dtype=np.float32), {
            'md5': md5_hash,
            'sha256': sha256_hash,
            'entropy': entropy,
            'file_size': file_size
        }
        
    except Exception as e:
        st.error(f"Error extracting features: {str(e)}")
        return np.zeros(100, dtype=np.float32), {}

def extract_pe_features(file_bytes):
    """Ekstraksi fitur dari PE file"""
    try:
        pe = pefile.PE(data=file_bytes)
        
        features = [
            len(pe.sections) / 10,  # Number of sections
            pe.FILE_HEADER.NumberOfSections / 10,
            pe.OPTIONAL_HEADER.SizeOfCode / 1000000,
            pe.OPTIONAL_HEADER.SizeOfInitializedData / 1000000,
            pe.OPTIONAL_HEADER.SizeOfUninitializedData / 1000000,
            len(pe.DIRECTORY_ENTRY_IMPORT) / 100 if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') else 0,
        ]
        
        # Section characteristics
        for section in pe.sections[:5]:  # First 5 sections
            features.append(section.SizeOfRawData / 1000000)
            features.append(section.Misc_VirtualSize / 1000000)
        
        # Pad if less than 5 sections
        while len(features) < 16:
            features.append(0.0)
            
        return features[:16]
        
    except:
        return [0.0] * 16

# YARA Rules
YARA_RULES = """
rule Suspicious_Executable
{
    meta:
        description = "Deteksi executable dengan karakteristik mencurigakan"
        author = "MalDetect AI"
    
    strings:
        $exec1 = "cmd.exe" nocase
        $exec2 = "powershell" nocase
        $exec3 = "rundll32" nocase
        $net1 = "http://" nocase
        $net2 = "https://" nocase
        $net3 = "download" nocase
        $registry = "HKEY_" nocase
        $persistence = "CurrentVersion\\\\Run" nocase
        
    condition:
        (2 of ($exec*)) or (2 of ($net*)) or ($registry and $persistence)
}

rule Ransomware_Indicators
{
    meta:
        description = "Indikator ransomware"
        author = "MalDetect AI"
    
    strings:
        $encrypt1 = "encrypt" nocase
        $encrypt2 = "decrypt" nocase
        $ransom1 = "bitcoin" nocase
        $ransom2 = "payment" nocase
        $ransom3 = "restore" nocase
        $file_ext = ".locked" nocase
        
    condition:
        ($encrypt1 and $encrypt2) and (2 of ($ransom*))
}

rule Keylogger_Behavior
{
    meta:
        description = "Perilaku keylogger"
        author = "MalDetect AI"
    
    strings:
        $key1 = "GetAsyncKeyState" nocase
        $key2 = "GetKeyboardState" nocase
        $key3 = "keylog" nocase
        $key4 = "keyboard" nocase
        
    condition:
        2 of them
}

rule Network_Communication
{
    meta:
        description = "Komunikasi jaringan mencurigakan"
        author = "MalDetect AI"
    
    strings:
        $ip_pattern = /\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b/
        $url = /https?:\\/\\/[a-zA-Z0-9\\-\\.]+\\.[a-zA-Z]{2,}/
        $socket = "socket" nocase
        $connect = "connect" nocase
        
    condition:
        ($ip_pattern or $url) and ($socket or $connect)
}
"""

def compile_yara_rules():
    """Compile YARA rules"""
    try:
        return yara.compile(source=YARA_RULES)
    except Exception as e:
        st.warning(f"YARA compilation warning: {str(e)}")
        return None

def scan_with_yara(file_bytes, rules):
    """Scan file dengan YARA rules"""
    if rules is None:
        return []
    
    try:
        matches = rules.match(data=file_bytes)
        return matches
    except Exception as e:
        st.warning(f"YARA scan warning: {str(e)}")
        return []

# Inisialisasi model
@st.cache_resource
def load_model():
    model = MalwareDetector(input_size=100)
    # Initialize with random weights (in production, load trained weights)
    model.eval()
    return model

def predict_malware(model, features):
    """Prediksi menggunakan model"""
    with torch.no_grad():
        features_tensor = torch.FloatTensor(features).unsqueeze(0)
        prediction = model(features_tensor)
        probability = prediction.item()
    return probability

def main():
    # Header
    st.title("🛡️ MalDetect AI")
    st.markdown("### Sistem Deteksi Malware dengan Machine Learning")
    st.markdown("---")
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/fluency/96/security-checked.png", width=80)
        st.markdown("## ⚙️ Pengaturan")
        
        threshold = st.slider(
            "Threshold Deteksi",
            min_value=0.0,
            max_value=1.0,
            value=0.5,
            step=0.05,
            help="Nilai ambang batas untuk klasifikasi malware"
        )
        
        enable_yara = st.checkbox("Aktifkan YARA Scan", value=True)
        
        st.markdown("---")
        st.markdown("### 📊 Statistik")
        if 'scan_history' not in st.session_state:
            st.session_state.scan_history = []
        
        total_scans = len(st.session_state.scan_history)
        malware_detected = sum(1 for s in st.session_state.scan_history if s['is_malware'])
        
        col1, col2 = st.columns(2)
        with col1:
            st.metric("Total Scan", total_scans)
        with col2:
            st.metric("Malware", malware_detected)
    
    # Main content tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Scan File", "📈 Analisis", "📋 Riwayat", "ℹ️ Info"])
    
    with tab1:
        st.markdown("## Upload File untuk Analisis")
        
        col1, col2 = st.columns([2, 1])
        
        with col1:
            uploaded_file = st.file_uploader(
                "Pilih file executable atau binary",
                type=['exe', 'dll', 'bin', 'sys', 'dat'],
                help="Upload file yang ingin dianalisis"
            )
        
        with col2:
            st.info("""
            **Format yang didukung:**
            - Windows PE (.exe, .dll, .sys)
            - Binary files (.bin, .dat)
            - Ukuran maks: 100MB
            """)
        
        if uploaded_file is not None:
            # Load model
            model = load_model()
            
            # Read file
            file_bytes = uploaded_file.read()
            file_name = uploaded_file.name
            
            st.success(f"✅ File '{file_name}' berhasil diupload ({len(file_bytes):,} bytes)")
            
            # Scanning progress
            progress_bar = st.progress(0)
            status_text = st.empty()
            
            # Step 1: Feature extraction
            status_text.text("🔬 Mengekstrak fitur...")
            progress_bar.progress(25)
            features, file_info = extract_features(file_bytes)
            
            # Step 2: ML prediction
            status_text.text("🧠 Analisis dengan Neural Network...")
            progress_bar.progress(50)
            ml_score = predict_malware(model, features)
            
            # Step 3: YARA scan
            yara_matches = []
            if enable_yara:
                status_text.text("🔎 YARA pattern matching...")
                progress_bar.progress(75)
                rules = compile_yara_rules()
                yara_matches = scan_with_yara(file_bytes, rules)
            
            # Step 4: Final analysis
            status_text.text("✨ Finalisasi hasil...")
            progress_bar.progress(100)
            
            # Clear progress
            progress_bar.empty()
            status_text.empty()
            
            # Determine if malware
            is_malware = ml_score > threshold or len(yara_matches) > 0
            
            # Display results
            st.markdown("---")
            st.markdown("## 📊 Hasil Analisis")
            
            # Main result card
            if is_malware:
                st.error("### ⚠️ MALWARE TERDETEKSI!")
                threat_level = "TINGGI" if ml_score > 0.8 else "SEDANG"
                st.markdown(f"**Tingkat Ancaman:** {threat_level}")
            else:
                st.success("### ✅ File Aman")
                st.markdown("**Tingkat Ancaman:** RENDAH")
            
            # Metrics
            col1, col2, col3, col4 = st.columns(4)
            
            with col1:
                st.metric(
                    "Skor ML",
                    f"{ml_score:.1%}",
                    delta=f"{(ml_score - threshold):.1%}" if ml_score > threshold else None,
                    delta_color="inverse"
                )
            
            with col2:
                st.metric("YARA Matches", len(yara_matches))
            
            with col3:
                st.metric("Entropy", f"{file_info.get('entropy', 0):.2f}")
            
            with col4:
                st.metric("Ukuran File", f"{file_info.get('file_size', 0) / 1024:.1f} KB")
            
            # Detailed analysis
            st.markdown("---")
            
            col1, col2 = st.columns(2)
            
            with col1:
                st.markdown("### 🔐 Hash Information")
                st.code(f"MD5:    {file_info.get('md5', 'N/A')}")
                st.code(f"SHA256: {file_info.get('sha256', 'N/A')}")
                
                st.markdown("### 🎯 ML Confidence")
                fig_gauge = go.Figure(go.Indicator(
                    mode="gauge+number",
                    value=ml_score * 100,
                    title={'text': "Malware Probability (%)"},
                    gauge={
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkred" if is_malware else "green"},
                        'steps': [
                            {'range': [0, 30], 'color': "lightgreen"},
                            {'range': [30, 70], 'color': "yellow"},
                            {'range': [70, 100], 'color': "lightcoral"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': threshold * 100
                        }
                    }
                ))
                fig_gauge.update_layout(height=250)
                st.plotly_chart(fig_gauge, use_container_width=True)
            
            with col2:
                if yara_matches and enable_yara:
                    st.markdown("### 🎯 YARA Detections")
                    for match in yara_matches:
                        with st.expander(f"🔴 {match.rule}", expanded=True):
                            st.markdown(f"**Namespace:** {match.namespace}")
                            if match.meta:
                                st.markdown("**Metadata:**")
                                for key, value in match.meta.items():
                                    st.markdown(f"- {key}: {value}")
                            if match.strings:
                                st.markdown("**Matched Strings:**")
                                for s in match.strings[:5]:  # Show first 5
                                    st.code(f"{s[2].decode('utf-8', errors='ignore')[:50]}")
                else:
                    st.markdown("### ✅ YARA Scan")
                    st.info("Tidak ada pattern mencurigakan terdeteksi")
                
                st.markdown("### 📊 Feature Distribution")
                fig_features = go.Figure(data=[
                    go.Bar(
                        x=[f"F{i}" for i in range(20)],
                        y=features[:20],
                        marker_color='indianred' if is_malware else 'lightseagreen'
                    )
                ])
                fig_features.update_layout(
                    title="Top 20 Features",
                    xaxis_title="Feature",
                    yaxis_title="Value",
                    height=250
                )
                st.plotly_chart(fig_features, use_container_width=True)
            
            # Recommendations
            st.markdown("---")
            st.markdown("### 💡 Rekomendasi")
            
            if is_malware:
                st.warning("""
                **Tindakan yang Disarankan:**
                1. 🚫 **JANGAN** jalankan file ini
                2. 🗑️ Hapus file dari sistem
                3. 🔒 Scan sistem dengan antivirus
                4. 🔄 Periksa file lain yang terkait
                5. 📋 Laporkan ke tim keamanan
                """)
                
                if ml_score > 0.8:
                    st.error("⚠️ **PERINGATAN:** Tingkat kepercayaan deteksi sangat tinggi!")
            else:
                st.success("""
                **Status:**
                - ✅ File tampak aman berdasarkan analisis
                - ✅ Tidak ada pattern berbahaya terdeteksi
                - ✅ Skor malware di bawah threshold
                
                **Catatan:** Tetap berhati-hati dengan file dari sumber tidak dikenal
                """)
            
            # Save to history
            scan_result = {
                'timestamp': datetime.now().isoformat(),
                'filename': file_name,
                'file_size': len(file_bytes),
                'ml_score': ml_score,
                'is_malware': is_malware,
                'yara_matches': len(yara_matches),
                'md5': file_info.get('md5', ''),
                'entropy': file_info.get('entropy', 0)
            }
            st.session_state.scan_history.append(scan_result)
    
    with tab2:
        st.markdown("## 📈 Analisis Mendalam")
        
        if 'scan_history' in st.session_state and st.session_state.scan_history:
            df = pd.DataFrame(st.session_state.scan_history)
            
            col1, col2 = st.columns(2)
            
            with col1:
                # Score distribution
                fig_dist = px.histogram(
                    df,
                    x='ml_score',
                    nbins=20,
                    title='Distribusi Skor ML',
                    color='is_malware',
                    color_discrete_map={True: 'red', False: 'green'}
                )
                st.plotly_chart(fig_dist, use_container_width=True)
                
                # File size vs score
                fig_scatter = px.scatter(
                    df,
                    x='file_size',
                    y='ml_score',
                    color='is_malware',
                    size='entropy',
                    hover_data=['filename'],
                    title='Ukuran File vs Skor ML',
                    color_discrete_map={True: 'red', False: 'green'}
                )
                st.plotly_chart(fig_scatter, use_container_width=True)
            
            with col2:
                # Detection rate over time
                df['timestamp'] = pd.to_datetime(df['timestamp'])
                df_time = df.set_index('timestamp').resample('1H').agg({
                    'is_malware': 'sum',
                    'ml_score': 'mean'
                }).reset_index()
                
                fig_time = go.Figure()
                fig_time.add_trace(go.Scatter(
                    x=df_time['timestamp'],
                    y=df_time['is_malware'],
                    name='Malware Detected',
                    fill='tozeroy'
                ))
                fig_time.update_layout(title='Deteksi Malware dari Waktu ke Waktu')
                st.plotly_chart(fig_time, use_container_width=True)
                
                # Entropy distribution
                fig_entropy = px.box(
                    df,
                    y='entropy',
                    x='is_malware',
                    color='is_malware',
                    title='Distribusi Entropy',
                    color_discrete_map={True: 'red', False: 'green'}
                )
                st.plotly_chart(fig_entropy, use_container_width=True)
        else:
            st.info("📊 Belum ada data analisis. Upload file untuk memulai scan.")
    
    with tab3:
        st.markdown("## 📋 Riwayat Scanning")
        
        if 'scan_history' in st.session_state and st.session_state.scan_history:
            df = pd.DataFrame(st.session_state.scan_history)
            df['timestamp'] = pd.to_datetime(df['timestamp'])
            df = df.sort_values('timestamp', ascending=False)
            
            # Filter
            col1, col2, col3 = st.columns(3)
            with col1:
                filter_status = st.selectbox(
                    "Filter Status",
                    ["Semua", "Malware", "Aman"]
                )
            with col2:
                st.write("")  # Spacing
            with col3:
                if st.button("🗑️ Clear History"):
                    st.session_state.scan_history = []
                    st.rerun()
            
            # Apply filter
            if filter_status == "Malware":
                df = df[df['is_malware'] == True]
            elif filter_status == "Aman":
                df = df[df['is_malware'] == False]
            
            # Display table
            st.dataframe(
                df[['timestamp', 'filename', 'file_size', 'ml_score', 'is_malware', 'yara_matches', 'entropy']].rename(columns={
                    'timestamp': 'Waktu',
                    'filename': 'Nama File',
                    'file_size': 'Ukuran (bytes)',
                    'ml_score': 'Skor ML',
                    'is_malware': 'Malware?',
                    'yara_matches': 'YARA Matches',
                    'entropy': 'Entropy'
                }),
                use_container_width=True,
                hide_index=True
            )
            
            # Export option
            if st.button("📥 Export to JSON"):
                json_str = json.dumps(st.session_state.scan_history, indent=2)
                st.download_button(
                    label="Download JSON",
                    data=json_str,
                    file_name=f"maldetect_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                    mime="application/json"
                )
        else:
            st.info("📋 Belum ada riwayat scanning.")
    
    with tab4:
        st.markdown("## ℹ️ Tentang MalDetect AI")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("""
            ### 🎯 Fitur Utama
            
            **Machine Learning Detection:**
            - Deep Neural Network dengan 5 layers
            - Batch Normalization dan Dropout
            - 100+ features extraction
            - Real-time prediction
            
            **YARA Rule Scanning:**
            - Pattern matching untuk malware
            - Multiple rule categories
            - Behavioral analysis
            - Custom rule support
            
            **Static Analysis:**
            - PE file parsing
            - Entropy calculation
            - Hash generation (MD5, SHA256)
            - Byte frequency analysis
            """)
        
        with col2:
            st.markdown("""
            ### 🔬 Metodologi
            
            **1. Feature Extraction:**
            - Entropy analysis
            - Byte frequency distribution
            - PE header information
            - Section characteristics
            - Statistical properties
            
            **2. ML Classification:**
            - PyTorch neural network
            - Probability-based scoring
            - Configurable threshold
            
            **3. Pattern Matching:**
            - YARA rules engine
            - Signature-based detection
            - Behavioral patterns
            
            **4. Risk Assessment:**
            - Combined scoring
            - Multi-layer verification
            - Confidence metrics
            """)
        
        st.markdown("---")
        st.markdown("""
        ### 📚 Teknologi yang Digunakan
        
        - **PyTorch**: Deep learning framework
        - **YARA**: Pattern matching engine
        - **pefile**: PE file parser
        - **Streamlit**: Web interface
        - **Plotly**: Interactive visualizations
        
        ### ⚠️ Disclaimer
        
        MalDetect AI adalah tool analisis untuk tujuan edukasi dan penelitian.
        Hasil deteksi harus diverifikasi dengan tools keamanan profesional lainnya.
        """)
        
        st.info("""
        💡 **Tips Penggunaan:**
        - Gunakan threshold 0.5 untuk deteksi seimbang
        - Aktifkan YARA untuk deteksi pattern-based
        - Perhatikan entropy tinggi (> 7.0) sebagai indikator kompresi/enkripsi
        - Review YARA matches untuk detail spesifik
        """)

if __name__ == "__main__":
    main()