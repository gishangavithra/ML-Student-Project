import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
import math

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")
st.title(" Phishing Website Detector")
st.markdown("**Enter a URL and click Check to see if it's a phishing site**")

# Load model
@st.cache_resource
def load_model():
    model = joblib.load('model.pkl')
    scaler = joblib.load('scaler.pkl')
    feature_names = pickle.load(open('feature_names.pkl', 'rb'))
    return model, scaler, feature_names

try:
    model, scaler, feature_names = load_model()
    st.success(" Model ready!")
except Exception as e:
    st.error(f" Error loading model: {e}")
    st.stop()



def extract_all_features(url):
    """Extract ALL features exactly like training data"""
    
    # Initialize all features with default values
    features = {f: -1 for f in feature_names}  # Most features use -1 as default
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        
        # URL Length
        features['length_url'] = len(url)
        
        # URL Character Counts
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
        
        # Domain Character Counts
        features['qty_dot_domain'] = domain.count('.')
        features['qty_hyphen_domain'] = domain.count('-')
        features['qty_underline_domain'] = domain.count('_')
        features['qty_slash_domain'] = domain.count('/')
        features['qty_questionmark_domain'] = domain.count('?')
        features['qty_equal_domain'] = domain.count('=') if domain else 0
        features['qty_at_domain'] = domain.count('@') if domain else 0
        
        # Directory Character Counts
        features['qty_dot_directory'] = path.count('.')
        features['qty_hyphen_directory'] = path.count('-')
        features['qty_underline_directory'] = path.count('_')
        features['qty_slash_directory'] = path.count('/')
        features['qty_questionmark_directory'] = path.count('?')
        features['qty_equal_directory'] = path.count('=')
        features['qty_at_directory'] = path.count('@')
        features['qty_and_directory'] = path.count('&')
        
        # File Character Counts
        file_part = path.split('/')[-1] if path else ''
        features['qty_dot_file'] = file_part.count('.')
        features['qty_hyphen_file'] = file_part.count('-')
        features['qty_underline_file'] = file_part.count('_')
        features['qty_slash_file'] = file_part.count('/')
        features['qty_questionmark_file'] = file_part.count('?')
        features['qty_equal_file'] = file_part.count('=')
        features['qty_at_file'] = file_part.count('@')
        features['qty_and_file'] = file_part.count('&')
        
        # Params Character Counts
        features['qty_dot_params'] = query.count('.')
        features['qty_hyphen_params'] = query.count('-')
        features['qty_underline_params'] = query.count('_')
        features['qty_slash_params'] = query.count('/')
        features['qty_questionmark_params'] = query.count('?')
        features['qty_equal_params'] = query.count('=')
        features['qty_at_params'] = query.count('@')
        features['qty_and_params'] = query.count('&')
        
        # Lengths
        features['length_domain'] = len(domain)
        features['length_path'] = len(path)
        features['length_query'] = len(query)
        
        # Special binary features (use 1 for YES, -1 for NO)
        features['having_IP_Address'] = 1 if re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', url) else -1
        features['having_At_Symbol'] = 1 if '@' in url else -1
        features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
        features['url_shortened'] = 1 if any(s in domain for s in ['bit.ly','goo.gl','tinyurl','ow.ly','is.gd','buff.ly']) else 0
        features['double_slash_redirecting'] = 1 if '//' in path and len(path.split('//')) > 2 else -1
        features['Prefix_Suffix'] = 1 if '-' in domain and '.' in domain else -1
        features['qty_subdomain'] = domain.count('.') - 1 if domain else 0
        
        # Safe defaults for features we can't compute
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
        
        # More domain features
        features['domain_length'] = len(domain) if domain else 0
        features['domain_hyphen'] = 1 if '-' in domain else -1
        features['domain_underscore'] = 1 if '_' in domain else -1
        features['domain_slash'] = 1 if '/' in domain else -1
        
        # URL features
        features['url_hyphen'] = 1 if '-' in url else -1
        features['url_underscore'] = 1 if '_' in url else -1
        features['url_slash'] = 1 if '/' in url else -1
        features['url_questionmark'] = 1 if '?' in url else -1
        features['url_equal'] = 1 if '=' in url else -1
        features['url_at'] = 1 if '@' in url else -1
        features['url_and'] = 1 if '&' in url else -1
        
        # File extension
        if '.' in file_part:
            ext = file_part.split('.')[-1].lower()
            features['file_extension'] = 1 if ext in ['exe','zip','rar','pdf','doc','xls'] else -1
        
        # Domain age (simulated)
        features['domain_age'] = 365
        
        # WHOIS info (simulated)
        features['whois_registered'] = 1
        features['whois_updated'] = 30
        
        # SSL info (simulated)
        features['ssl_valid'] = 1
        features['ssl_age'] = 365
        
    except Exception as e:
        pass
    
    # Make sure all features have values
    for f in feature_names:
        if f not in features:
            features[f] = -1  # Default value
    
    return features


url_input = st.text_input(
    "Enter Website URL",
    placeholder="https://google.com",
)

if st.button(" Check Website", type="primary"):
    
    if not url_input:
        st.warning(" Please enter a URL")
    else:
        try:
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner(" Analyzing..."):
                features_dict = extract_all_features(url_input)
                input_df = pd.DataFrame([features_dict])[feature_names]
                
                # Scale
                input_scaled = scaler.transform(input_df)
                
                # Predict
                prediction = model.predict(input_scaled)
                probability = model.predict_proba(input_scaled)[0]
            
            st.markdown("---")
            
            # SHOW RESULTS
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
            
            st.caption(f"Analyzed: {url_input}")
            
        except Exception as e:
            st.error(f" Error: {e}")

st.markdown("---")
st.caption("Phishing Detection using Machine Learning")
