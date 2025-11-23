import json
import os
import gzip 
from datetime import datetime, timedelta
from langchain_community.vectorstores import FAISS 
from langchain_huggingface import HuggingFaceEmbeddings
from langchain_ollama import ChatOllama
from langchain.chains import ConversationalRetrievalChain
from langchain.schema import Document
from langchain.schema.messages import SystemMessage, HumanMessage, AIMessage
import argparse
import shutil 
from flask import Flask, render_template, request, jsonify, session

app = Flask(__name__)
app.secret_key ="secret_key_for_wazuh_chatbot" 

class Config:
    OLLAMA_SERVER_URL = "http://172.18.225.183:11434" 
    CHAT_MODEL_NAME = "llama3.1:8b" 
    EMBEDDING_MODEL_NAME = "all-MiniLM-L6-v2" 
    WAZUH_LOG_PATH = "/var/ossec/logs/archives" 
    VECTOR_DB_PATH = "wazuh_faiss_db" 
    PAST_DAYS_TO_LOAD = 7
qa_chain = None
context = None
vectorstore_db = None

def load_logs_from_local(past_days=Config.PAST_DAYS_TO_LOAD):
    print(f"Loading logs locally from {Config.WAZUH_LOG_PATH} for the past {past_days} days...")
    logs = []
    today = datetime.now()
    total_files_processed = 0
    total_lines_read = 0

    for i in range(past_days):
        day = today - timedelta(days=i)
        year = day.year
        month_name = day.strftime("%b") 
        day_num = day.strftime("%d")

        json_path = f"{Config.WAZUH_LOG_PATH}/{year}/{month_name}/ossec-archive-{day_num}.json"
        gz_path = f"{Config.WAZUH_LOG_PATH}/{year}/{month_name}/ossec-archive-{day_num}.json.gz"

        file_path_to_open = None
        open_func = None

        if os.path.exists(json_path) and os.path.getsize(json_path) > 0:
            file_path_to_open = json_path
            open_func = open
        elif os.path.exists(gz_path) and os.path.getsize(gz_path) > 0:
            file_path_to_open = gz_path
            open_func = gzip.open
        else:
            print(f"    WARNING: Log file missing or empty for {day.strftime('%Y-%m-%d')}: {json_path} / {gz_path}")
            continue

        print(f"    Processing file: {file_path_to_open}")
        total_files_processed += 1
        lines_in_file = 0
        try:
            with open_func(file_path_to_open, 'rt', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines_read += 1
                    lines_in_file += 1
                    if line.strip():
                        try:
                            log = json.loads(line.strip())
                            logs.append(log)
                        except json.JSONDecodeError:
                            if lines_in_file % 500 == 0: 
                                print(f"        Skipping invalid JSON line in {file_path_to_open} (line {lines_in_file})...")
        except Exception as e:
            print(f"    ERROR: Reading {file_path_to_open}: {e}")
        
        print(f"    Read {lines_in_file} lines from {file_path_to_open}. Total logs collected so far: {len(logs)}")

    current_log_file = os.path.join(Config.WAZUH_LOG_PATH, 'archives.json')
    if os.path.exists(current_log_file) and os.path.getsize(current_log_file) > 0:
        print(f"    Processing current file: {current_log_file}")
        total_files_processed += 1
        lines_in_file = 0
        try:
            with open(current_log_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    total_lines_read += 1
                    lines_in_file += 1
                    if line.strip():
                        try:
                            log = json.loads(line.strip())
                            logs.append(log)
                        except json.JSONDecodeError:
                            if lines_in_file % 500 == 0: 
                                print(f"        Skipping invalid JSON line in {current_log_file} (line {lines_in_file})...")
        except Exception as e:
            print(f"    ERROR: Reading {current_log_file}: {e}")
        print(f"    Read {lines_in_file} lines from {current_log_file}. Total logs collected so far: {len(logs)}")

    print(f"Finished loading logs. Total files processed: {total_files_processed}, total lines read: {total_lines_read}, total raw logs collected: {len(logs)}")
    return logs

def preprocess_log_document(log_dict: dict) -> Document | None:
    if not isinstance(log_dict, dict): return None
    location = log_dict.get("location", "")
    if location == "sca": return None 
    rule_level = log_dict.get("rule", {}).get("level", 0)
    if rule_level < 5: return None 

    agent_name = log_dict.get("agent", {}).get("name", "N/A"); rule_id = log_dict.get("rule", {}).get("id", "N/A"); rule_desc = log_dict.get("rule", {}).get("description", "N/A"); timestamp = log_dict.get("timestamp", "N/A"); src_ip = log_dict.get("srcip", ""); dst_ip = log_dict.get("dstip", ""); user = log_dict.get("data", {}).get("user", "")
    searchable_parts = [ f"Agent: {agent_name}", f"Rule ID: {rule_id}", f"Rule Description: {rule_desc}", f"Timestamp: {timestamp}"]
    if location: searchable_parts.append(f"Location: {location}")
    if src_ip: searchable_parts.append(f"Source IP: {src_ip}")
    if dst_ip: searchable_parts.append(f"Destination IP: {dst_ip}")
    if user: searchable_parts.append(f"User: {user}")
    
    win_data = log_dict.get("data", {}).get("win", {}); ossec_decoded = log_dict.get("data", {}).get("ossec", {}).get("decoded", {})
    if win_data: 
        system_info = win_data.get("system", {}); event_data = win_data.get("eventdata", {})
        searchable_parts.extend([f"Windows Event ID: {system_info.get('eventID', '')}", f"Windows Message: {system_info.get('message', '')}", f"Provider: {system_info.get('providerName', '')}", f"Process Name: {event_data.get('ProcessName', '') or system_info.get('processName', '')}", f"Target User Name: {event_data.get('TargetUserName', '')}"])
    elif ossec_decoded:
        searchable_parts.extend([f"Program: {ossec_decoded.get('program_name', '')}", f"Linux User: {ossec_decoded.get('user', '')}", f"Command: {ossec_decoded.get('command', '')}", f"Status: {ossec_decoded.get('status', '')}"])
        
    full_log_content = log_dict.get("full_log", "")
    if full_log_content and len(full_log_content) > 50 and len(full_log_content) < 1000: searchable_parts.append(f"Full Log Snippet: {full_log_content[:200]}...")
    
    final_searchable_text = ". ".join([part for part in searchable_parts if part and part.split(': ')[-1].strip()])
    if not final_searchable_text or len(final_searchable_text) < 50: return None
    
    metadata = {"original_log_json": json.dumps(log_dict, ensure_ascii=False)}
    return Document(page_content=final_searchable_text, metadata=metadata)

def create_or_load_vectorstore(logs, embedding_model):
    global vectorstore_db

    if os.path.exists(Config.VECTOR_DB_PATH):
        print(f"Loading existing vectorstore from '{Config.VECTOR_DB_PATH}'...")
        try:
    
            vectorstore_db = FAISS.load_local(Config.VECTOR_DB_PATH, embedding_model, allow_dangerous_deserialization=True)
            print("Vectorstore loaded successfully.")
            return vectorstore_db
        except Exception as e:
            print(f"Could not load existing vectorstore: {e}. Rebuilding...")
            shutil.rmtree(Config.VECTOR_DB_PATH, ignore_errors=True)
            vectorstore_db = None 

    print("Starting document preprocessing...")
    documents = []
    processed_count = 0
    skipped_count = 0
    for log_dict in logs:
        doc = preprocess_log_document(log_dict)
        if doc:
            documents.append(doc)
            processed_count += 1
            if processed_count % 1000 == 0: print(f"    Processed {processed_count} logs into documents...")
        else:
            skipped_count += 1
    
    if not documents:
        print("    ERROR: No valid documents created for vectorstore.")
        return None

    print(f"Finished preprocessing. Created {len(documents)} documents. Skipped {skipped_count} logs.")
    print(f"Creating FAISS vectorstore...")
    try:
        vectorstore_db = FAISS.from_documents(documents, embedding_model)
        print("FAISS vectorstore created successfully.")
        
        print(f"Saving new vectorstore to '{Config.VECTOR_DB_PATH}'...")
        vectorstore_db.save_local(Config.VECTOR_DB_PATH)
        print("Vectorstore saved successfully.")
        return vectorstore_db
    except Exception as e:
        print(f"    ERROR: Failed to create or save FAISS vectorstore: {e}")
        return None

def summarize_log_for_display(log_dict):

    if not isinstance(log_dict, dict): return {"error": "Invalid log format"}
    summary = {"timestamp": log_dict.get("timestamp"), "agent_name": log_dict.get("agent", {}).get("name"), "rule_description": log_dict.get("rule", {}).get("description"), "rule_id": log_dict.get("rule", {}).get("id"), "rule_level": log_dict.get("rule", {}).get("level"), "location": log_dict.get("location"), "src_ip": log_dict.get("srcip"), "dst_ip": log_dict.get("dstip"), "user": log_dict.get("data", {}).get("user")}
    win_data = log_dict.get("data", {}).get("win", {}); ossec_decoded = log_dict.get("data", {}).get("ossec", {}).get("decoded", {})
    if win_data: system_info = win_data.get("system", {}); event_data = win_data.get("eventdata", {}); summary.update({"win_provider_name": system_info.get("providerName"), "win_event_id": system_info.get("eventID"), "win_severity_value": system_info.get("severityValue"), "win_message": system_info.get("message"), "win_process_id": system_info.get("processID"), "win_process_name": system_info.get("processName"), "win_target_user_name": event_data.get("TargetUserName"), "win_param1": event_data.get("param1"), "win_file_name": event_data.get("FileName"), "win_image": event_data.get("Image"), "win_status": event_data.get("Status")})
    elif ossec_decoded: summary.update({"linux_program_name": ossec_decoded.get("program_name"), "linux_user": ossec_decoded.get("user"), "linux_status": ossec_decoded.get("status"), "linux_src_ip": ossec_decoded.get("srcip"), "linux_dst_ip": ossec_decoded.get("dstip"), "linux_action": ossec_decoded.get("action"), "linux_process": ossec_decoded.get("process"), "linux_command": ossec_decoded.get("command"), "linux_full_log": log_dict.get("full_log")})
    if "predecoder" in log_dict: summary["predecoder_program_name"] = log_dict.get("predecoder", {}).get("program_name")
    if "syslog" in log_dict: summary["syslog_program_name"] = log_dict.get("syslog", {}).get("program_name"); summary["syslog_host"] = log_dict.get("syslog", {}).get("host"); summary["syslog_priority"] = log_dict.get("syslog", {}).get("priority")
    final_summary = {k: v for k, v in summary.items() if v is not None and v != ""}
    return final_summary

def initialize_assistant_context():
    return """
**Persona:** You are a helpful and expert Security Analyst Bot.
Your goal is to assist me in analyzing Wazuh logs and understanding security threats.

**CRITICAL RULES:**
1.  **Determine User Intent:** First, analyze the user's LATEST question.
    * **Intent 1: Log Analysis (e.g., "find", "search", "investigate", "analyze", "show me logs"):**
        If the user wants you to find specific events, your task is to analyze the `Context Logs` provided. Look deep into the JSON data (like `data.win.eventdata`, `srcip`, `win_event_id`).
        You MUST respond using the **'Analyst's Report'** format.
    * **Intent 2: General Question (e.g., "how to prevent...", "what is...", "explain this"):**
        If the user is
        asking for advice, definitions, or explanations, your task is to provide a clear, direct answer.
        You should use the `Chat History` and `Context Logs` for context (e.g., to understand what "this vulnerability" refers to), but you MUST respond with a normal, conversational answer.
        **DO NOT** use the 'Analyst's Report' format for general questions.

2.  **Context is Key:** Always use the `Chat History` to understand follow-up questions.

3.  **If No Logs Found:** If the user intended to search (Intent 1) but the `Context Logs` are empty or irrelevant, respond ONLY with: `No relevant security events found matching the query.`

---
**Analyst's Report Format (Use ONLY for Intent 1)**

**Observation:**
(State the key facts found in the JSON data. What happened? Which agent? Which rule_id? Which win_event_id? BE FACTUAL.)

**Hypothesis:**
(Based ONLY on the facts, what is your security hypothesis? E.g., "Event ID 4616 indicates a system time change...")

**Recommendation:**
(Provide specific, actionable next steps based on your hypothesis.)
"""

def setup_chain(past_days=Config.PAST_DAYS_TO_LOAD, force_rebuild=False):
    global qa_chain, context, vectorstore_db

    print(f"\n--- Initializing QA Chain ---")
    
    embedding_model = HuggingFaceEmbeddings(model_name=Config.EMBEDDING_MODEL_NAME)
    print(f"Embedding model '{Config.EMBEDDING_MODEL_NAME}' initialized.")
    
    vectorstore_exists = os.path.exists(Config.VECTOR_DB_PATH)

    if force_rebuild or not vectorstore_exists:
        if force_rebuild and vectorstore_exists:
            print(f"Force rebuild requested. Deleting existing vectorstore at '{Config.VECTOR_DB_PATH}'...")
            shutil.rmtree(Config.VECTOR_DB_PATH, ignore_errors=True)
        
        print(f"Creating new vectorstore with logs from past {past_days} days...")
        logs = load_logs_from_local(past_days)
        if not logs:
            print("No logs found. Skipping chain setup. Chatbot will not be initialized.")
            qa_chain = None; vectorstore_db = None
            return
        print(f"{len(logs)} raw logs successfully loaded for processing.")
        
        vectorstore_db = create_or_load_vectorstore(logs, embedding_model)
        if vectorstore_db is None:
            print("Failed to create vectorstore. Chatbot will not be initialized.")
            qa_chain = None
            return
    else:
        
        vectorstore_db = create_or_load_vectorstore(None, embedding_model) 
        if vectorstore_db is None:
             print("Failed to load vectorstore. Chatbot will not be initialized.")
             qa_chain = None
             return

    print(f"Connecting to Ollama at {Config.OLLAMA_SERVER_URL} using model '{Config.CHAT_MODEL_NAME}'...")
    try:
        llm = ChatOllama(base_url=Config.OLLAMA_SERVER_URL, model=Config.CHAT_MODEL_NAME)
        
        llm.invoke("Hi") 
        print("Ollama connection successful.")
    except Exception as e:
        print(f"ERROR: Could not connect to Ollama server at {Config.OLLAMA_SERVER_URL}. Please ensure it is running and accessible. Error: {e}")
        qa_chain = None
        return

    context = initialize_assistant_context()

    qa_chain = ConversationalRetrievalChain.from_llm(
        llm=llm,
        retriever=vectorstore_db.as_retriever(search_kwargs={"k": 5}),
        return_source_documents=True
    )
    print("QA chain initialized successfully.")
    print("--- QA Chain Ready ---")

@app.route('/')
def home():
    session.clear()
    session['chat_history'] = []
    return render_template('index.html')

@app.route('/chat', methods=['POST'])
def chat():
    global qa_chain

    if not qa_chain:
        return jsonify({'response': "Chatbot is not initialized. Please try again later."}),500

    user_input = request.json.get('message', '')
    if not user_input:
        return jsonify({'response': "Please enter a message."}),400
    
    chat_history = []
    if 'chat_history' in session:
        for msg in session['chat_history']:
            if msg['role'] == 'user':
                chat_history.append(HumanMessage(content=msg['content']))
            elif msg['role'] == 'bot':
                chat_history.append(AIMessage(content=msg['content']))

    chain_input = {"question": user_input, "chat_history": chat_history}

    try:
        response = qa_chain.invoke(chain_input)
        answer = response.get("answer", "").replace("\\n", "\n").strip()
        source_documents = response.get("source_documents", [])
        
        session['chat_history'].append({'role': 'user', 'content': user_input})
        session['chat_history'].append({'role': 'bot', 'content': answer})
        session.modified = True

        referenced_logs = []
        if source_documents and "Analyst's Report" in answer:
            displayed_log_signatures = set()
            for doc in source_documents:
                try:
                    original_log_dict = json.loads(doc.metadata.get('original_log_json', '{}'))
                    summarized_log = summarize_log_for_display(original_log_dict)
                    
                    agent_name = summarized_log.get("agent_name", "N/A")
                    rule_id = summarized_log.get("rule_id", "N/A")
                    core_info = f"{summarized_log.get('win_event_id', '')}-{summarized_log.get('rule_description', '')[:30]}"
                    log_signature = f"{agent_name}|{rule_id}|{core_info}"

                    if log_signature not in displayed_log_signatures:
                        referenced_logs.append(summarized_log)
                        displayed_log_signatures.add(log_signature)
                except json.JSONDecodeError:
                    pass

        return jsonify({
            "answer": answer,
            "logs": referenced_logs
        })
    except Exception as e:
        print(f"Error during chat processing: {e}")
        return jsonify({'response': "An error occurred while processing your request."}),500

if __name__ == "__main__":

    setup_chain()
    app.run(host='0.0.0.0', port=5000, debug=True)



