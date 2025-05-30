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

# Core libraries
import nltk
from nltk.corpus import stopwords
from nltk.tokenize import word_tokenize
import string

# Download required NLTK data
@st.cache_resource
def download_nltk_data():
    try:
        nltk.data.find('tokenizers/punkt')
    except LookupError:
        nltk.download('punkt')
    
    try:
        nltk.data.find('corpora/stopwords')
    except LookupError:
        nltk.download('stopwords')

class MITREMapper:
    def _init_(self, use_semantic=True):
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
            self.use_semantic = False
        except Exception as e:
            self.use_semantic = False

    def extract_keywords(self, text):
        """Extract meaningful keywords from alert text"""
        try:
            stop_words = set(stopwords.words('english') + list(string.punctuation))
            words = word_tokenize(text.lower())
            keywords = [word for word in words if word.isalpha() and len(word) > 2 and word not in stop_words]
            return keywords
        except:
            # Fallback to simple splitting if NLTK fails
            words = re.findall(r'\b[a-zA-Z]{3,}\b', text.lower())
            common_stop_words = {'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had', 'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his', 'how', 'man', 'new', 'now', 'old', 'see', 'two', 'way', 'who', 'boy', 'did', 'its', 'let', 'put', 'say', 'she', 'too', 'use'}
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

# Initialize the mapper (cached for performance)
@st.cache_resource
def get_mitre_mapper():
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
        
        # Extract rule name/text
        rule_text = input_data.get('rulename', '') or input_data.get('rule_text', '') or input_data.get('text', '')
        top_k = input_data.get('top_k', 1)
        
        if not rule_text:
            return {
                "status": "error",
                "message": "No rule text provided. Please include 'rulename', 'rule_text', or 'text' in your JSON input.",
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

# Streamlit App
def main():
    st.set_page_config(
        page_title="MITRE ATT&CK Mapping Platform",
        page_icon="🛡",
        layout="wide"
    )
    
    st.title("🛡 MITRE ATT&CK Mapping Platform")
    st.markdown("Map security rules and alerts to MITRE ATT&CK techniques using exact matching and semantic similarity.")
    
    # Create tabs
    tab1, tab2, tab3 = st.tabs(["🔍 Interactive Mapping", "🔌 API Interface", "📖 Documentation"])
    
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
                    placeholder="e.g., Attacker injects arbitrary code into the genuine live process..."
                )
                top_k = st.slider("Number of results to return:", 1, 5, 1)
                
                if st.button("🔍 Map to MITRE ATT&CK", type="primary"):
                    if rule_text:
                        with st.spinner("Analyzing and mapping to MITRE ATT&CK..."):
                            json_input = {"rulename": rule_text, "top_k": top_k}
                            result = process_mitre_mapping(json_input)
                            
                            # Display results
                            if result["status"] == "success":
                                st.success(f"✅ Found {result['total_matches']} match(es)")
                                
                                for i, match in enumerate(result["results"], 1):
                                    with st.expander(f"#{i} - {match['technique_name']} ({match['technique_id']})"):
                                        col_a, col_b = st.columns(2)
                                        with col_a:
                                            st.write(f"*Confidence Score:* {match['confidence_score']}")
                                            
                                        with col_b:
                                            st.write(f"*Tactics:* {', '.join(match['tactics']) if match['tactics'] else 'None'}")
                                        
                            else:
                                st.error(f"❌ {result['message']}")
                    else:
                        st.warning("Please enter some text to analyze.")
            
            else:  # JSON Input
                json_input_text = st.text_area(
                    "Enter JSON input:",
                    height=150,
                    placeholder='{"rulename": "Your security rule description here", "top_k": 1}'
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
            except:
                st.metric("Status", "⚠ Loading...")
    
    with tab2:
        st.header("🔌 API Interface")
        st.markdown("Use these endpoints to integrate with your applications:")
        
        # API endpoints info
        st.subheader("Endpoint Information")
        base_url = st.text_input("Your Streamlit App URL:", value="http://localhost:8501")
        
        st.code(f"""
# API Endpoint (if deployed with API framework)
POST {base_url}/api/map

# Example using curl:
curl -X POST "{base_url}/api/map" \\
  -H "Content-Type: application/json" \\
  -d '{{"rulename": "Suspicious process injection detected", "top_k": 2}}'
        """, language="bash")
        
        st.subheader("📥 Input Format")
        st.json({
            "rulename": "Your security rule or alert description",
            "top_k": 1
        })
        
        st.subheader("📤 Output Format")
        st.json({
            "status": "success",
            "input_text": "Your input text",
            "total_matches": 1,
            "results": [
                {
                    "technique_id": "T1055",
                    "technique_name": "Process Injection",
                    "confidence_score": 0.95,
                    "match_method": "exact_name",
                    "tactics": ["defense-evasion", "privilege-escalation"],
                    "description": "Adversaries may inject code into processes..."
                }
            ]
        })
        
        st.subheader("🧪 Test API")
        test_json = st.text_area(
            "Test JSON input:",
            value='{"rulename": "Process injection attack detected", "top_k": 2}',
            height=100
        )
        
        if st.button("🧪 Test API Call"):
            result = process_mitre_mapping(test_json)
            st.json(result)
    
    with tab3:
        st.header("📖 Documentation")
        
        st.subheader("🎯 Purpose")
        st.markdown("""
        This platform maps security rules, alerts, and threat descriptions to MITRE ATT&CK techniques using:
        - *Exact Name Matching*: Direct matching of technique names
        - *Keyword Matching*: Partial word matching with scoring
        - *Semantic Similarity*: AI-powered contextual matching using sentence transformers
        """)
        
        st.subheader("📝 Input Options")
        st.markdown("""
        *JSON Fields (at least one required):*
        - rulename: Main rule/alert description
        - rule_text: Alternative field for rule text
        - text: Generic text field
        - top_k: Number of results to return (default: 1)
        """)
        
        st.subheader("🔧 Integration with n8n")
        st.markdown("""
        *Step 1:* Deploy this Streamlit app
        *Step 2:* Use HTTP Request node in n8n
        *Step 3:* Configure POST request to your Streamlit app
        *Step 4:* Set Content-Type to application/json
        *Step 5:* Send JSON payload with rule description
        """)
        
        st.subheader("⚙ Installation Requirements")
        st.code("""
pip install streamlit attackcti sentence-transformers nltk requests urllib3
        """, language="bash")
        
        st.subheader("🚀 Running the App")
        st.code("""
streamlit run mitre_app.py --server.port 8501
        """, language="bash")

if __name__ == "__main__":
    main()
