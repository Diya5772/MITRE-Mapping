import streamlit as st
import json
import re
import time
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from typing import List, Tuple, Dict, Optional
import warnings
warnings.filterwarnings('ignore')
import string
import threading
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import os

# Try to import NLTK with graceful fallback
try:
    import nltk
    from nltk.corpus import stopwords
    from nltk.tokenize import word_tokenize
    NLTK_AVAILABLE = True
except ImportError:
    NLTK_AVAILABLE = False
    st.warning("⚠️ NLTK not installed. Using basic text processing. Install with: pip install nltk")

# Your existing MITREMapper class (keeping the same code)
class MITREMapper:
    def __init__(self, use_semantic=True):
        """
        Initialize the MITRE ATT&CK mapper
        
        Args:
            use_semantic (bool): Whether to use semantic similarity matching
        """
        self.mitre_data = {}
        self.use_semantic = use_semantic
        self.model = None
        self.mitre_embeddings = None
        self.mitre_texts = []
        self.mitre_ids = []
        
        # Load MITRE data
        self._load_mitre_data()
        
        # Initialize semantic components if requested
        if self.use_semantic:
            self._initialize_semantic_matching()

    def _load_mitre_data(self):
        """Load MITRE ATT&CK data with multiple fallback methods"""
        
        # Try multiple methods in order of preference
        methods = [
            self._load_from_attackcti,
            self._load_from_mitre_github,
        ]

        for method in methods:
            try:
                self.mitre_data = method()
                if self.mitre_data:
                    return
            except Exception as e:
                continue

        raise Exception("All data loading methods failed")

    def _load_from_attackcti(self):
        """Load data using attackcti library"""
        try:
            from attackcti import attack_client

            client = attack_client()
            techniques = client.get_enterprise_techniques()

            mitre_data = {}
            for technique in techniques:
                if hasattr(technique, 'external_references') and technique.external_references:
                    technique_id = technique.external_references[0].get('external_id', '')
                    if technique_id.startswith('T'):
                        tactics = []
                        if hasattr(technique, 'kill_chain_phases') and technique.kill_chain_phases:
                            tactics = [phase.phase_name for phase in technique.kill_chain_phases]

                        mitre_data[technique_id] = {
                            'name': technique.name or '',
                            'description': getattr(technique, 'description', '') or '',
                            'tactics': tactics
                        }

            return mitre_data

        except Exception as e:
            raise

    def _load_from_mitre_github(self):
        """Load data directly from MITRE's GitHub repository"""
        try:
            # Configure session with retry strategy
            session = requests.Session()
            retry_strategy = Retry(
                total=3,
                backoff_factor=1,
                status_forcelist=[429, 500, 502, 503, 504],
            )
            adapter = HTTPAdapter(max_retries=retry_strategy)
            session.mount("http://", adapter)
            session.mount("https://", adapter)

            url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
            response = session.get(url, timeout=60)
            response.raise_for_status()

            # Parse JSON with proper error handling
            try:
                data = response.json()
            except json.JSONDecodeError as e:
                # Try to clean the JSON response
                text = response.text.strip()
                if text.startswith('\ufeff'):  # Remove BOM if present
                    text = text[1:]
                data = json.loads(text)

            mitre_data = {}
            for obj in data.get('objects', []):
                if (obj.get('type') == 'attack-pattern' and
                    not obj.get('revoked', False) and
                    not obj.get('x_mitre_deprecated', False)):

                    # Extract technique ID
                    ext_refs = obj.get('external_references', [])
                    technique_id = None
                    for ref in ext_refs:
                        if ref.get('source_name') == 'mitre-attack':
                            technique_id = ref.get('external_id')
                            break

                    # Extract tactics
                    tactics = []
                    kill_chain_phases = obj.get('kill_chain_phases', [])
                    for phase in kill_chain_phases:
                        if phase.get('kill_chain_name') == 'mitre-attack':
                            tactics.append(phase.get('phase_name', ''))

                    if technique_id and technique_id.startswith('T'):
                        mitre_data[technique_id] = {
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'tactics': tactics
                        }

            return mitre_data

        except Exception as e:
            raise

    def _initialize_semantic_matching(self):
        """Initialize semantic matching components"""
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            # Load the model
            self.model = SentenceTransformer('all-MiniLM-L6-v2')

            # Prepare texts for embedding
            self.mitre_ids = list(self.mitre_data.keys())
            self.mitre_texts = []

            for tid in self.mitre_ids:
                data = self.mitre_data[tid]
                # Combine name and description for better matching
                text = f"{data['name']} {data['description']}"
                self.mitre_texts.append(text)

            # Generate embeddings
            self.mitre_embeddings = self.model.encode(self.mitre_texts, convert_to_tensor=True)

        except ImportError:
            st.warning("⚠️ sentence-transformers not installed. Semantic matching disabled.")
            self.use_semantic = False
        except Exception as e:
            st.warning(f"⚠️ Semantic matching initialization failed: {str(e)}")
            self.use_semantic = False

    def extract_keywords(self, text):
        """Extract meaningful keywords from alert text"""
        if NLTK_AVAILABLE:
            try:
                # Download stopwords if not available
                try:
                    stop_words = set(stopwords.words('english'))
                except LookupError:
                    try:
                        nltk.download('stopwords')
                        stop_words = set(stopwords.words('english'))
                    except:
                        stop_words = set()
                
                stop_words.update(set(string.punctuation))
                
                # Tokenize with fallback
                try:
                    words = word_tokenize(text.lower())
                except LookupError:
                    try:
                        nltk.download('punkt')
                        words = word_tokenize(text.lower())
                    except:
                        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
                
                keywords = [word for word in words if word.isalpha() and len(word) > 2 and word not in stop_words]
                return keywords
            except Exception as e:
                # Fall through to basic processing
                pass
        
        # Fallback to simple splitting if NLTK fails or unavailable
        words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
        common_stop_words = {
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 
            'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 
            'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 
            'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use', 'with', 'from',
            'they', 'this', 'that', 'will', 'been', 'have', 'were', 'said', 'each',
            'which', 'their', 'time', 'into', 'than', 'only', 'come', 'very', 'after'
        }
        return [word for word in words if word not in common_stop_words]

    def exact_name_matching(self, alert_text, keywords):
        """Perform exact name matching"""
        matches = []
        alert_lower = alert_text.lower()

        for tid, data in self.mitre_data.items():
            name_lower = data['name'].lower()

            # Check if technique name appears in alert
            if name_lower in alert_lower:
                matches.append((tid, data['name'], 1.0, 'exact_name', data['tactics']))
                continue

            # Check if any keyword matches technique name words
            name_words = set(re.findall(r'\b[a-zA-Z]{3,}\b', name_lower))
            keyword_matches = name_words.intersection(set(keywords))

            if keyword_matches:
                score = len(keyword_matches) / len(name_words) if name_words else 0
                if score > 0.3:  # At least 30% word overlap
                    matches.append((tid, data['name'], score, 'keyword_match', data['tactics']))

        return matches

    def semantic_matching(self, alert_text, top_k=1, threshold=0.3):
        """Perform semantic similarity matching"""
        if not self.use_semantic or not self.model:
            return []

        try:
            from sentence_transformers.util import cos_sim

            # Generate embedding for alert text
            alert_embedding = self.model.encode(alert_text, convert_to_tensor=True)

            # Calculate similarities
            similarities = cos_sim(alert_embedding, self.mitre_embeddings)[0]

            # Get top matches above threshold
            matches = []
            top_indices = similarities.argsort(descending=True)

            for idx in top_indices[:top_k]:
                score = similarities[idx].item()
                if score >= threshold:
                    tid = self.mitre_ids[idx]
                    data = self.mitre_data[tid]
                    matches.append((tid, data['name'], score, 'semantic', data['tactics']))

            return matches

        except Exception as e:
            st.warning(f"⚠️ Semantic matching failed: {str(e)}")
            return []

    def map_alert_to_mitre(self, alert_text, combine_methods=True, top_k=1):
        """
        Map alert text to MITRE ATT&CK techniques

        Args:
            alert_text (str): The alert or rule description
            combine_methods (bool): Whether to combine exact and semantic matching
            top_k (int): Maximum number of results to return

        Returns:
            List of tuples: (technique_id, technique_name, score, match_type, tactics)
        """
        # Extract keywords
        keywords = self.extract_keywords(alert_text)

        all_matches = []

        # Exact name matching
        exact_matches = self.exact_name_matching(alert_text, keywords)
        all_matches.extend(exact_matches)

        # Semantic matching
        if self.use_semantic:
            semantic_matches = self.semantic_matching(alert_text, top_k=top_k)
            all_matches.extend(semantic_matches)

        # Remove duplicates and sort by score
        seen_ids = set()
        unique_matches = []
        for match in sorted(all_matches, key=lambda x: x[2], reverse=True):
            if match[0] not in seen_ids:
                unique_matches.append(match)
                seen_ids.add(match[0])

        # Limit results
        final_matches = unique_matches[:top_k]

        return final_matches

# Download required NLTK data
@st.cache_resource
def download_nltk_data():
    if not NLTK_AVAILABLE:
        return False
    
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        try:
            nltk.download('punkt')
        except Exception:
            return False
    
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        try:
            nltk.download('stopwords')
        except Exception:
            return False
    
    return True

# Initialize the mapper (cached for performance)
@st.cache_resource
def get_mitre_mapper():
    if NLTK_AVAILABLE:
        download_nltk_data()
    return MITREMapper(use_semantic=True)

# Function to process JSON input and return JSON output
def process_mitre_mapping(json_input):
    """Process MITRE mapping request and return JSON response"""
    try:
        # Parse input JSON
        if isinstance(json_input, str):
            input_data = json.loads(json_input)
        else:
            input_data = json_input
        
        # Extract rule name/text - support n8n format
        rule_text = (input_data.get('ruleName', '') or 
                    input_data.get('rulename', '') or 
                    input_data.get('rule_text', '') or 
                    input_data.get('text', ''))
        top_k = input_data.get('top_k', 1)
        
        if not rule_text:
            return {
                "status": "error",
                "message": "No rule text provided. Please include 'ruleName', 'rulename', 'rule_text', or 'text' in your JSON input.",
                "results": []
            }
        
        # Get mapper instance
        mapper = get_mitre_mapper()
        
        # Perform mapping
        matches = mapper.map_alert_to_mitre(rule_text, top_k=top_k)
        
        # Format results
        results = []
        for tid, name, score, match_type, tactics in matches:
            results.append({
                "technique_id": tid,
                "technique_name": name,
                "confidence_score": round(score, 3),
                "match_method": match_type,
                "tactics": tactics,
                "description": mapper.mitre_data[tid].get('description', '')[:200] + "..." if len(mapper.mitre_data[tid].get('description', '')) > 200 else mapper.mitre_data[tid].get('description', '')
            })
        
        return {
            "status": "success",
            "input_text": rule_text,
            "total_matches": len(results),
            "results": results
        }
        
    except json.JSONDecodeError:
        return {
            "status": "error",
            "message": "Invalid JSON format in input",
            "results": []
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Processing error: {str(e)}",
            "results": []
        }

# Flask API for n8n integration
flask_app = Flask(__name__)
CORS(flask_app)  # Enable CORS for cross-origin requests

@flask_app.route('/api/map', methods=['POST'])
def api_map_rule():
    """API endpoint for mapping single rule to MITRE ATT&CK"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400
        
        # Process using existing function
        result = process_mitre_mapping(data)
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@flask_app.route('/api/map-batch', methods=['POST'])
def api_map_multiple_rules():
    """API endpoint for mapping multiple rules to MITRE ATT&CK"""
    try:
        data = request.get_json()
        
        if not data or not isinstance(data, list):
            return jsonify({"error": "Expected array of rule objects"}), 400
        
        results = []
        for item in data:
            result = process_mitre_mapping(item)
            results.append(result)
        
        return jsonify({
            "batch_results": results,
            "total_processed": len(data),
            "success_count": sum(1 for r in results if r.get("status") == "success"),
            "error_count": sum(1 for r in results if r.get("status") == "error")
        })
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@flask_app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        mapper = get_mitre_mapper()
        return jsonify({
            "status": "healthy",
            "service": "MITRE Mapping API",
            "techniques_loaded": len(mapper.mitre_data),
            "semantic_enabled": mapper.use_semantic
        })
    except Exception as e:
        return jsonify({"status": "unhealthy", "error": str(e)}), 500

@flask_app.route('/api/docs', methods=['GET'])
def api_docs():
    """API documentation endpoint"""
    return jsonify({
        "service": "MITRE ATT&CK Mapping API",
        "version": "1.0.0",
        "endpoints": {
            "/api/map": {
                "method": "POST",
                "description": "Map single rule to MITRE ATT&CK",
                "input": {"ruleName": "string", "top_k": "integer (optional)"},
                "output": {"status": "string", "results": "array"}
            },
            "/api/map-batch": {
                "method": "POST", 
                "description": "Map multiple rules to MITRE ATT&CK",
                "input": "array of rule objects",
                "output": {"batch_results": "array", "total_processed": "integer"}
            },
            "/api/health": {
                "method": "GET",
                "description": "Health check",
                "output": {"status": "string", "techniques_loaded": "integer"}
            }
        },
        "example_input": {
            "ruleName": "Ransomware Multiple File Extension Change Activity Detected on System",
            "top_k": 1
        }
    })

def run_flask():
    """Run Flask API in a separate thread"""
    try:
        flask_app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
    except Exception as e:
        print(f"Flask startup error: {e}")

# Start Flask API in background
if 'flask_started' not in st.session_state:
    try:
        flask_thread = threading.Thread(target=run_flask, daemon=True)
        flask_thread.start()
        st.session_state.flask_started = True
        time.sleep(2)  # Give Flask time to start
    except Exception as e:
        st.error(f"Failed to start API server: {e}")

# Streamlit App (keeping your existing UI)
def main():
    st.set_page_config(
        page_title="MITRE ATT&CK Mapping Platform",
        page_icon="🛡️",
        layout="wide"
    )
    
    st.title("🛡️ MITRE ATT&CK Mapping Platform")
    st.markdown("Map security rules and alerts to MITRE ATT&CK techniques using exact matching and semantic similarity.")
    
    # API Status indicator
    st.sidebar.markdown("### 🔌 API Status")
    try:
        response = requests.get("http://localhost:5000/api/health", timeout=5)
        if response.status_code == 200:
            st.sidebar.success("✅ API Server Online")
            health_data = response.json()
            st.sidebar.info(f"📊 {health_data.get('techniques_loaded', 0)} techniques loaded")
        else:
            st.sidebar.error("❌ API Server Error")
    except:
        st.sidebar.warning("⚠️ API Server Starting...")
    
    # Create tabs
    tab1, tab2, tab3, tab4 = st.tabs(["🔍 Interactive Mapping", "🔌 API Interface", "🧪 n8n Testing", "📖 Documentation"])
    
    with tab1:
        st.header("Interactive MITRE Mapping")
        
        # Input section
        col1, col2 = st.columns([2, 1])
        
        with col1:
            input_method = st.radio("Choose input method:", ["Text Input", "JSON Input"])
            
            if input_method == "Text Input":
                rule_text = st.text_area(
                    "Enter your security rule or alert description:",
                    height=100,
                    placeholder="e.g., Ransomware Multiple File Extension Change Activity Detected on System"
                )
                top_k = st.slider("Number of results to return:", 1, 5, 1)
                
                if st.button("🔍 Map to MITRE ATT&CK", type="primary"):
                    if rule_text:
                        with st.spinner("Analyzing and mapping to MITRE ATT&CK..."):
                            json_input = {"ruleName": rule_text, "top_k": top_k}
                            result = process_mitre_mapping(json_input)
                            
                            # Display results
                            if result["status"] == "success":
                                st.success(f"✅ Found {result['total_matches']} match(es)")
                                
                                for i, match in enumerate(result["results"], 1):
                                    with st.expander(f"#{i} - {match['technique_name']} ({match['technique_id']})"):
                                        col_a, col_b = st.columns(2)
                                        with col_a:
                                            st.write(f"**Confidence Score:** {match['confidence_score']}")
                                            st.write(f"**Match Method:** {match['match_method']}")
                                        with col_b:
                                            st.write(f"**Tactics:** {', '.join(match['tactics']) if match['tactics'] else 'None'}")
                                        st.write(f"**Description:** {match['description']}")
                            else:
                                st.error(f"❌ {result['message']}")
                    else:
                        st.warning("Please enter some text to analyze.")
            
            else:  # JSON Input
                json_input_text = st.text_area(
                    "Enter JSON input:",
                    height=150,
                    placeholder='{"ruleName": "Your security rule description here", "top_k": 1}'
                )
                
                if st.button("🔍 Process JSON Input", type="primary"):
                    if json_input_text:
                        with st.spinner("Processing JSON input..."):
                            result = process_mitre_mapping(json_input_text)
                            
                            # Display results
                            if result["status"] == "success":
                                st.success(f"✅ Found {result['total_matches']} match(es)")
                                st.json(result)
                            else:
                                st.error(f"❌ {result['message']}")
                                st.json(result)
                    else:
                        st.warning("Please enter JSON input.")
        
        with col2:
            st.subheader("📊 Quick Stats")
            try:
                mapper = get_mitre_mapper()
                st.metric("Total MITRE Techniques", len(mapper.mitre_data))
                st.metric("Semantic Matching", "✅ Enabled" if mapper.use_semantic else "❌ Disabled")
            except Exception as e:
                st.metric("Status", "⚠️ Loading...")
                st.error(f"Error loading mapper: {str(e)}")
    
    with tab2:
        st.header("🔌 API Interface")
        st.markdown("Use these endpoints to integrate with your applications:")
        
        # Get current URL
        current_url = st.text_input("Your Streamlit App URL:", 
                                   value="https://diya5772-mitre-mapping-app-iubskf.streamlit.app")
        
        st.subheader("📡 Available Endpoints")
        
        endpoints = {
            "/api/map": "Map single rule to MITRE ATT&CK",
            "/api/map-batch": "Map multiple rules to MITRE ATT&CK", 
            "/api/health": "Health check",
            "/api/docs": "API documentation"
        }
        
        for endpoint, description in endpoints.items():
            st.code(f"POST {current_url}{endpoint}")
            st.write(f"📝 {description}")
        
        st.subheader("📥 Input Format (for n8n)")
        st.json({
            "ruleName": "Ransomware Multiple File Extension Change Activity Detected on System"
        })
        
        st.subheader("📤 Output Format")
        st.json({
            "status": "success",
            "input_text": "Ransomware Multiple File Extension Change Activity Detected on System",
            "total_matches": 1,
            "results": [
                {
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "confidence_score": 0.95,
                    "match_method": "exact_name",
                    "tactics": ["impact"],
                    "description": "Adversaries may encrypt data on target systems..."
                }
            ]
        })
    
    with tab3:
        st.header("🧪 n8n Integration Testing")
        st.markdown("Test your API endpoints for n8n integration:")
        
        # Test single mapping
        st.subheader("Test Single Rule Mapping")
        test_rule = st.text_input("Rule to test:", 
                                 value="Ransomware Multiple File Extension Change Activity Detected on System")
        
        if st.button("🧪 Test API Call"):
            if test_rule:
                try:
                    test_data = {"ruleName": test_rule}
                    response = requests.post("http://localhost:5000/api/map", 
                                           json=test_data, 
                                           timeout=30)
                    
                    if response.status_code == 200:
                        st.success("✅ API Response Successful!")
                        result = response.json()
                        st.json(result)
                        
                        # Show n8n-formatted output
                        st.subheader("📤 n8n Output Format")
                        if result.get("status") == "success" and result.get("results"):
                            first_result = result["results"][0]
                            n8n_output = {
                                "ruleName": test_rule,
                                "techniqueId": first_result.get("technique_id"),
                                "techniqueName": first_result.get("technique_name"),
                                "tactics": first_result.get("tactics", []),
                                "confidenceScore": first_result.get("confidence_score"),
                                "description": first_result.get("description")
                            }
                            st.json(n8n_output)
                    else:
                        st.error(f"❌ API Error: {response.status_code}")
                        st.text(response.text)
                except Exception as e:
                    st.error(f"🔌 Connection error: {str(e)}")
                    st.info("💡 Make sure the API server is running. Try refreshing the page.")
        
        # Test batch mapping
        st.subheader("Test Batch Rule Mapping")
        st.markdown("Test with multiple rules (like n8n array input):")
        
        batch_test_data = [
            {"ruleName": "Ransomware Multiple File Extension Change Activity Detected on System"},
            {"ruleName": "Suspicious process injection detected"}
        ]
        
        st.json(batch_test_data)
        
        if st.button("🧪 Test Batch API Call"):
            try:
                response = requests.post("http://localhost:5000/api/map-batch", 
                                       json=batch_test_data, 
                                       timeout=30)
                
                if response.status_code == 200:
                    st.success("✅ Batch API Response Successful!")
                    st.json(response.json())
                else:
                    st.error(f"❌ Batch API Error: {response.status_code}")
                    st.text(response.text)
            except Exception as e:
                st.error(f"🔌 Batch connection error: {str(e)}")
    
    with tab4:
        st.header("📖 n8n Integration Documentation")
        
        st.subheader("🎯 Quick Setup for n8n")
        st.markdown("""
        **Step 1:** Use your deployed Streamlit app URL  
        **Step 2:** Add HTTP Request node in n8n  
        **Step 3:** Configure as shown below  
        """)
        
        st.subheader("⚙️ n8n HTTP Request Node Configuration")
        
        config_data = {
            "Method": "POST",
            "URL": f"{current_url}/api/map",
            "Headers": {
                "Content-Type": "application/json"
            },
            "Body": {
                "Type": "JSON",
                "Content": '{{ JSON.stringify($json) }}'
            }
        }
        
        st.json(config_data)
        
        st.subheader("📥 Expected n8n Input Format")
        st.markdown("Your previous node should output:")
        st.json([{"ruleName": "Ransomware Multiple File Extension Change Activity Detected on System"}])
        
        st.subheader("📤 n8n Output Format")
        st.markdown("The HTTP Request node will return:")
        st.json({
            "status": "success",
            "input_text": "Ransomware Multiple File Extension Change Activity Detected on System",
            "total_matches": 1,
            "results": [
                {
                    "technique_id": "T1486",
                    "technique_name": "Data Encrypted for Impact",
                    "confidence_score": 0.95,
                    "match_method": "exact_name",
                    "tactics": ["impact"],
                    "description": "Adversaries may encrypt data on target systems..."
                }
            ]
        })
        
        st.subheader("🔄 Processing the Output in n8n")
        st.markdown("""
        **To extract specific values in n8n, use these expressions:**
        
        - **First technique ID:** `{{ $json.results[0].technique_id }}`
        - **First technique name:** `{{ $json.results[0].technique_name }}`
        - **All tactics:** `{{ $json.results[0].tactics }}`
        - **Confidence score:** `{{ $json.results[0].confidence_score }}`
        """)
        
        st.subheader("⚠️ Error Handling in n8n")
        st.markdown("""
        **Always check the status field:**
        ```javascript
        // In n8n Function node
        if ($json.status === 'success') {
            return {
                success: true,
                techniqueId: $json.results[0]?.technique_id,
                techniqueName: $json.results[0]?.technique_name,
                tactics: $json.results[0]?.tactics || []
            };
        } else {
            return {
                success: false,
                error: $json.message
            };
        }
        ```
        """)
        
        st.subheader("📋 Installation Requirements")
        st.markdown("**Add to your `requirements.txt`:**")
        st.code("""streamlit
requests
urllib3
sentence-transformers
nltk
attackcti
torch
flask
flask-cors""", language="text")

if __name__ == "__main__":
    main()