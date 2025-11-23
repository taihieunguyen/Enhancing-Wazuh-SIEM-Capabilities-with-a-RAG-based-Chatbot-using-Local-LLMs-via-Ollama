# Enhancing-Wazuh-SIEM-Capabilities-with-a-RAG-based-Chatbot-using-Local-LLMs-via-Ollama
Building a Local RAG Architecture for Wazuh SIEM. By vectorizing logs for semantic search, the system automates threat hunting and incident response analysis. This solution reduces alert fatigue and ensures complete data privacy by processing all sensitive information entirely within the internal network.
# Key Features
- 100% Private & Secure: All data processing occurs locally within your network. No logs are sent to cloud APIs (like OpenAI), ensuring strict compliance with data privacy regulations.
- Hybrid RAG Architecture: Fast Build: Processes hundreds of thousands of historical logs in seconds using a static refinement algorithm.
- Smart Stream: Monitors logs in real-time (Watcher) and utilizes a lightweight AI model to deeply analyze and refine each new alert as it arrives.
- Automated Analyst Report: The chatbot automatically synthesizes information and generates reports following the standard format: Observation -> Hypothesis -> Recommendation
- Interactive UI: A user-friendly Web UI (built with Flask) that supports chat history and displays detailed referenced log excerpts (Citations)

# Architecture
<img width="1191" height="566" alt="image" src="https://github.com/user-attachments/assets/18c74f97-0d5e-47dc-b6db-325179bfaa2a" />

# Key Components
- SIEM: Wazuh handles log collection, Intrusion Detection (IDS), and File Integrity Monitoring (FIM).
- LLM Server: Ollama hosts and executes local AI models securely on WSL/Linux.
- Chat Model: llama3.1:8b performs context analysis, answers user queries, and generates detailed reports.
- Embedding: all-MiniLM-L6-v2 converts logs and user queries into vector embeddings.
- Vector DB: FAISS manages high-performance vector storage and similarity search.
- Backend: Python and LangChain orchestrate the application logic and RAG pipeline.
- Frontend: Flask, HTML, and JavaScript deliver a user-friendly web interface.

# Prerequisites
To deploy this system, ensure your environment meets the following requirements:
Hardware:
- CPU: Minimum 4 cores (8 cores recommended).
- RAM: Minimum: 16GB (to run Wazuh + Llama 3.1 8B) (Recommended: 32GB or a dedicated GPU (NVIDIA) for faster inference speeds.)
- Disk: 50GB+ free space for logs and models.
Software:
- OS: Ubuntu Server 22.04 LTS (or running via WSL2 on Windows).
- Wazuh: Installed and active (Server & Agents).
- Python: Version 3.10 or higher.
- Ollama: Installed with necessary models pulled.

# Getting Started
1. Install Dependencies:
```bash
pip install flask langchain-community langchain-huggingface langchain-ollama faiss-cpu watchdog
```
2. Prepare Models (via Ollama):
```bash
ollama pull llama3.1:8b
ollama pull phi3:mini
```
3. Configuration:
Edit the app.py file to point to your correct Wazuh log paths and Ollama Server IP:
```bash
class Config:
    OLLAMA_SERVER_URL = "http://localhost:11434"
    WAZUH_ALERTS_PATH = "/var/ossec/logs/alerts"
```
4. Launch the Chatbot:
```bash
python app.py
```
# References
1. https://wazuh.com/blog/leveraging-artificial-intelligence-for-threat-hunting-in-wazuh/
2. https://blog.pytoshka.me/post/wazuh-integration-with-ollama-part-1/
3. https://www.datacamp.com/tutorial/llama-3-1-rag
