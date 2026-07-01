import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
import requests
import socket
from datetime import datetime

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")

# Title with your student ID
st.title(" Phishing Website Detector")
st.markdown("**COM763-Advanced Machine Learning**")
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
    """Extract features from URL with better defaults"""
    
    features = {}
    
    # Initialize all features
    for f in feature_names:
        features[f] = -1
    
    try:
        # Clean URL
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        
   
        features['length_url'] = min(len(url), 1000)  # Cap at 1000
        
        # Count special characters in URL
        features['qty_dot_url'] = min(url.count('.'), 20)
        features['qty_hyphen_url'] = min(url.count('-'), 20)
        features['qty_underline_url'] = min(url.count('_'), 20)
        features['qty_slash_url'] = min(url.count('/'), 20)
        features['qty_questionmark_url'] = min(url.count('?'), 10)
        features['qty_equal_url'] = min(url.count('='), 10)
        features['qty_at_url'] = min(url.count('@'), 5)
        features['qty_and_url'] = min(url.count('&'), 10)
        features['qty_exclamation_url'] = min(url.count('!'), 5)
        features['qty_space_url'] = min(url.count(' '), 5)
        features['qty_tilde_url'] = min(url.count('~'), 5)
        features['qty_comma_url'] = min(url.count(','), 5)
        features['qty_plus_url'] = min(url.count('+'), 5)
        features['qty_asterisk_url'] = min(url.count('*'), 5)
        features['qty_hashtag_url'] = min(url.count('#'), 5)
        features['qty_dollar_url'] = min(url.count('$'), 5)
        features['qty_percent_url'] = min(url.count('%'), 5)
        
      
        if domain:
            features['qty_dot_domain'] = min(domain.count('.'), 10)
            features['qty_hyphen_domain'] = min(domain.count('-'), 10)
            features['qty_underline_domain'] = min(domain.count('_'), 10)
            features['qty_slash_domain'] = min(domain.count('/'), 5)
            features['qty_questionmark_domain'] = min(domain.count('?'), 5)
            features['qty_equal_domain'] = min(domain.count('='), 5)
            features['qty_at_domain'] = min(domain.count('@'), 5)
            features['length_domain'] = min(len(domain), 100)
        
        
        if path:
            features['qty_dot_directory'] = min(path.count('.'), 10)
            features['qty_hyphen_directory'] = min(path.count('-'), 10)
            features['qty_underline_directory'] = min(path.count('_'), 10)
            features['qty_slash_directory'] = min(path.count('/'), 20)
            features['qty_questionmark_directory'] = min(path.count('?'), 5)
            features['qty_equal_directory'] = min(path.count('='), 5)
            features['qty_at_directory'] = min(path.count('@'), 5)
            features['qty_and_directory'] = min(path.count('&'), 5)
            features['length_path'] = min(len(path), 200)
            
            # File part
            file_part = path.split('/')[-1] if path else ''
            if file_part:
                features['qty_dot_file'] = min(file_part.count('.'), 5)
                features['qty_hyphen_file'] = min(file_part.count('-'), 5)
                features['qty_underline_file'] = min(file_part.count('_'), 5)
                features['qty_slash_file'] = min(file_part.count('/'), 5)
                features['qty_questionmark_file'] = min(file_part.count('?'), 5)
                features['qty_equal_file'] = min(file_part.count('='), 5)
                features['qty_at_file'] = min(file_part.count('@'), 5)
                features['qty_and_file'] = min(file_part.count('&'), 5)
        
        
        if query:
            features['qty_dot_params'] = min(query.count('.'), 10)
            features['qty_hyphen_params'] = min(query.count('-'), 10)
            features['qty_underline_params'] = min(query.count('_'), 10)
            features['qty_slash_params'] = min(query.count('/'), 10)
            features['qty_questionmark_params'] = min(query.count('?'), 5)
            features['qty_equal_params'] = min(query.count('='), 10)
            features['qty_at_params'] = min(query.count('@'), 5)
            features['qty_and_params'] = min(query.count('&'), 10)
            features['length_query'] = min(len(query), 200)
        
        
        # IP Address detection
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        features['having_IP_Address'] = 1 if re.search(ip_pattern, url) else -1
        
        # @ Symbol
        features['having_At_Symbol'] = 1 if '@' in url else -1
        
        # HTTPS
        features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
        
        # URL shorteners
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'short.url', 'rb.gy']
        features['url_shortened'] = 1 if any(s in domain for s in shorteners) else 0
        
        # Double slash redirecting
        features['double_slash_redirecting'] = 1 if '//' in path and path.count('//') > 1 else -1
        
        # Prefix/Suffix
        features['Prefix_Suffix'] = 1 if '-' in domain else -1
        
        # Subdomain count
        features['qty_subdomain'] = max(0, domain.count('.') - 1) if domain else 0
        
        
        # These are simulated but better approximate real values
        features['url_google_index'] = 1  # Assume indexed
        features['domain_google_index'] = 1  # Assume indexed
        features['time_response'] = 50  # Good response time
        features['time_domain_activation'] = 500  # Days since activation (simulated)
        features['time_domain_expiration'] = 365  # Days until expiration
        features['qty_ip_resolved'] = 1
        features['qty_nameservers'] = 2
        features['qty_mx_servers'] = 1
        features['ttl_hostname'] = 86400  # 24 hours
        features['qty_redirects'] = 0
        
        # Additional features
        features['domain_age'] = 365  # 1 year old (simulated)
        features['whois_registered'] = 1
        features['whois_updated'] = 30
        features['ssl_valid'] = 1
        features['ssl_age'] = 365
        
    except Exception as e:
        st.warning(f"Error extracting features: {e}")
    
    return features



if 'url_input' not in st.session_state:
    st.session_state.url_input = ""

url_input = st.text_input(
    "Enter Website URL",
    value=st.session_state.url_input,
    placeholder="https://google.com",
    key="url_input_field"
)

st.session_state.url_input = url_input

if st.button(" Check Website", type="primary", use_container_width=True):
    
    url_to_check = st.session_state.url_input.strip()
    
    if not url_to_check:
        st.warning(" Please enter a URL")
    else:
        try:
            # Fix URL
            if not url_to_check.startswith(('http://', 'https://')):
                url_to_check = 'http://' + url_to_check
            
            # Remove duplicate protocols
            if url_to_check.count('://') > 1:
                first_protocol_end = url_to_check.find('://') + 3
                url_to_check = url_to_check[:first_protocol_end] + url_to_check[first_protocol_end:].replace('http://', '').replace('https://', '')
            
            # Extract domain for display
            parsed = urlparse(url_to_check)
            display_domain = parsed.netloc
            
            with st.spinner(f" Analyzing {display_domain}..."):
                features_dict = extract_all_features(url_to_check)
                input_df = pd.DataFrame([features_dict])[feature_names]
                
                # Scale
                input_scaled = scaler.transform(input_df)
                
                # Predict
                prediction = model.predict(input_scaled)
                probability = model.predict_proba(input_scaled)[0]
            
            # Show results
            st.markdown("---")
            
            # Show analyzed URL
            st.caption(f" Analyzed: {display_domain}")
            st.caption(f" Full URL: {url_to_check}")
            
            # Results
            if prediction[0] == 1:
                st.error(" **PHISHING DETECTED!**")
                st.warning(f" {display_domain} appears to be a PHISHING site")
                col1, col2 = st.columns(2)
                col1.metric(" Phishing Confidence", f"{probability[1]*100:.1f}%", delta="High Risk")
                col2.metric(" Legitimate Confidence", f"{probability[0]*100:.1f}%", delta="Low")
            else:
                st.success(" **SAFE WEBSITE!**")
                st.success(f" {display_domain} appears to be LEGITIMATE")
                col1, col2 = st.columns(2)
                col1.metric(" Legitimate Confidence", f"{probability[0]*100:.1f}%", delta="High")
                col2.metric(" Phishing Confidence", f"{probability[1]*100:.1f}%", delta="Low")
            
            # Warning for suspicious domains
            if any(x in display_domain for x in ['xyz', 'club', 'online', 'top']):
                st.info(" Note: .xyz, .club, .online domains are sometimes used for phishing. Always verify the website carefully.")
            
        except Exception as e:
            st.error(f" Error: {e}")

# Footer
st.markdown("---")
st.caption("S25021283 - Lokuwaduge Gishan Gavithra De Silva | COM763 - Advanced Machine Learning |  Phishing Detection using Machine Learning")

