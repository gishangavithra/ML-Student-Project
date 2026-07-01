import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")

# Title with your student ID
st.title(" Phishing Website Detector")
st.markdown("**S25021283 - Lokuwaduge Gishan Gavithra De Silva**")
st.markdown("Enter a URL and click Check to see if it's a phishing site")

# Load model
@st.cache_resource
def load_model():
    try:
        model = joblib.load('model.pkl')
        scaler = joblib.load('scaler.pkl')
        feature_names = pickle.load(open('feature_names.pkl', 'rb'))
        return model, scaler, feature_names
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None, None, None

model, scaler, feature_names = load_model()

if model is not None:
    st.success(" Model ready!")
else:
    st.error(" Model not loaded")
    st.stop()



def extract_all_features(url):
    """Extract features from URL"""
    
    features = {}
    
    # Initialize all features with default values
    for f in feature_names:
        features[f] = -1
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        
        # URL counts
        features['length_url'] = len(url)
        features['qty_dot_url'] = url.count('.')
        features['qty_hyphen_url'] = url.count('-')
        features['qty_underline_url'] = url.count('_')
        features['qty_slash_url'] = url.count('/')
        features['qty_questionmark_url'] = url.count('?')
        features['qty_equal_url'] = url.count('=')
        features['qty_at_url'] = url.count('@')
        features['qty_and_url'] = url.count('&')
        features['qty_exclamation_url'] = url.count('!')
        features['qty_space_url'] = url.count(' ')
        features['qty_tilde_url'] = url.count('~')
        features['qty_comma_url'] = url.count(',')
        features['qty_plus_url'] = url.count('+')
        features['qty_asterisk_url'] = url.count('*')
        features['qty_hashtag_url'] = url.count('#')
        features['qty_dollar_url'] = url.count('$')
        features['qty_percent_url'] = url.count('%')
        
        # Domain counts
        if domain:
            features['qty_dot_domain'] = domain.count('.')
            features['qty_hyphen_domain'] = domain.count('-')
            features['qty_underline_domain'] = domain.count('_')
            features['qty_slash_domain'] = domain.count('/')
            features['qty_questionmark_domain'] = domain.count('?')
            features['qty_equal_domain'] = domain.count('=')
            features['qty_at_domain'] = domain.count('@')
            features['length_domain'] = len(domain)
        
        # Directory counts
        if path:
            features['qty_dot_directory'] = path.count('.')
            features['qty_hyphen_directory'] = path.count('-')
            features['qty_underline_directory'] = path.count('_')
            features['qty_slash_directory'] = path.count('/')
            features['qty_questionmark_directory'] = path.count('?')
            features['qty_equal_directory'] = path.count('=')
            features['qty_at_directory'] = path.count('@')
            features['qty_and_directory'] = path.count('&')
            features['length_path'] = len(path)
            
            # File part
            file_part = path.split('/')[-1]
            if file_part:
                features['qty_dot_file'] = file_part.count('.')
                features['qty_hyphen_file'] = file_part.count('-')
                features['qty_underline_file'] = file_part.count('_')
                features['qty_slash_file'] = file_part.count('/')
                features['qty_questionmark_file'] = file_part.count('?')
                features['qty_equal_file'] = file_part.count('=')
                features['qty_at_file'] = file_part.count('@')
                features['qty_and_file'] = file_part.count('&')
        
        # Query counts
        if query:
            features['qty_dot_params'] = query.count('.')
            features['qty_hyphen_params'] = query.count('-')
            features['qty_underline_params'] = query.count('_')
            features['qty_slash_params'] = query.count('/')
            features['qty_questionmark_params'] = query.count('?')
            features['qty_equal_params'] = query.count('=')
            features['qty_at_params'] = query.count('@')
            features['qty_and_params'] = query.count('&')
            features['length_query'] = len(query)
        
        # Special features
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        features['having_IP_Address'] = 1 if re.search(ip_pattern, url) else -1
        features['having_At_Symbol'] = 1 if '@' in url else -1
        features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly']
        features['url_shortened'] = 1 if any(s in domain for s in shorteners) else 0
        
        features['double_slash_redirecting'] = 1 if '//' in path and path.count('//') > 1 else -1
        features['Prefix_Suffix'] = 1 if '-' in domain else -1
        features['qty_subdomain'] = domain.count('.') - 1 if domain else 0
        
        # Default values for features we can't compute
        features['url_google_index'] = 1
        features['domain_google_index'] = 1
        features['time_response'] = 100
        features['time_domain_activation'] = 1000
        features['time_domain_expiration'] = 10000
        features['qty_ip_resolved'] = 1
        features['qty_nameservers'] = 2
        features['qty_mx_servers'] = 1
        features['ttl_hostname'] = 1000
        features['qty_redirects'] = 0
        
        # Additional features
        features['domain_age'] = 365
        features['whois_registered'] = 1
        features['whois_updated'] = 30
        features['ssl_valid'] = 1
        features['ssl_age'] = 365
        
    except Exception as e:
        st.warning(f"Error extracting features: {e}")
    
    return features



# Initialize session state
if 'url_input' not in st.session_state:
    st.session_state.url_input = ""

# Text input
url_input = st.text_input(
    "Enter Website URL",
    value=st.session_state.url_input,
    placeholder="https://google.com",
    key="url_input_field"
)

# Update session state
st.session_state.url_input = url_input

# Check button
if st.button("🔍 Check Website", type="primary", use_container_width=True):
    
    # Get URL from session state and clean it
    url_to_check = st.session_state.url_input.strip()
    
    if not url_to_check:
        st.warning(" Please enter a URL")
    else:
        try:
            # Clean the URL - FIX: Only add http:// if NO protocol exists
            if not url_to_check.startswith(('http://', 'https://')):
                url_to_check = 'http://' + url_to_check
            
            # FIX: Remove any duplicate http:// or https://
            # If there are multiple protocols, keep only the first one
            if url_to_check.count('://') > 1:
                # Find the first :// and take everything from there
                first_protocol_end = url_to_check.find('://') + 3
                url_to_check = url_to_check[:first_protocol_end] + url_to_check[first_protocol_end:].replace('http://', '').replace('https://', '')
            
            with st.spinner(" Analyzing website..."):
                # Extract features
                features_dict = extract_all_features(url_to_check)
                
                # Create DataFrame
                input_df = pd.DataFrame([features_dict])[feature_names]
                
                # Scale
                input_scaled = scaler.transform(input_df)
                
                # Predict
                prediction = model.predict(input_scaled)
                probability = model.predict_proba(input_scaled)[0]
            
            # Show results
            st.markdown("---")
            
            if prediction[0] == 1:
                st.error(" **PHISHING DETECTED!**")
                st.warning(f" This website appears to be a PHISHING site")
                col1, col2 = st.columns(2)
                col1.metric("Phishing Confidence", f"{probability[1]*100:.1f}%")
                col2.metric("Legitimate Confidence", f"{probability[0]*100:.1f}%")
            else:
                st.success(" **SAFE WEBSITE!**")
                st.success(f" This website appears to be LEGITIMATE")
                col1, col2 = st.columns(2)
                col1.metric("Legitimate Confidence", f"{probability[0]*100:.1f}%")
                col2.metric("Phishing Confidence", f"{probability[1]*100:.1f}%")
            
            st.caption(f"Analyzed: {url_to_check}")
            
        except Exception as e:
            st.error(f" Error: {e}")
            st.info("Please check the URL and try again")

# Footer with student ID
st.markdown("---")
st.caption("S25021283 - Lokuwaduge Gishan Gavithra De Silva | Phishing Detection using Machine Learning")
