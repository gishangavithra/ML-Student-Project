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

# Title
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
    """Extract ALL 111 features for the model"""
    
    # Start with all features = 0
    features = {f: 0 for f in feature_names}
    
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        
        # URL Length
        features['length_url'] = len(url)
        
        # Count characters in URL
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
        features['qty_dot_domain'] = domain.count('.')
        features['qty_hyphen_domain'] = domain.count('-')
        features['qty_underline_domain'] = domain.count('_')
        features['qty_slash_domain'] = domain.count('/')
        features['qty_questionmark_domain'] = domain.count('?')
        features['qty_equal_domain'] = domain.count('=')
        features['qty_at_domain'] = domain.count('@')
        features['qty_and_domain'] = domain.count('&')
        features['qty_exclamation_domain'] = domain.count('!')
        features['qty_space_domain'] = domain.count(' ')
        features['qty_tilde_domain'] = domain.count('~')
        features['qty_comma_domain'] = domain.count(',')
        features['qty_plus_domain'] = domain.count('+')
        features['qty_asterisk_domain'] = domain.count('*')
        features['qty_hashtag_domain'] = domain.count('#')
        features['qty_dollar_domain'] = domain.count('$')
        features['qty_percent_domain'] = domain.count('%')
        
        # Directory counts
        features['qty_dot_directory'] = path.count('.')
        features['qty_hyphen_directory'] = path.count('-')
        features['qty_underline_directory'] = path.count('_')
        features['qty_slash_directory'] = path.count('/')
        features['qty_questionmark_directory'] = path.count('?')
        features['qty_equal_directory'] = path.count('=')
        features['qty_at_directory'] = path.count('@')
        features['qty_and_directory'] = path.count('&')
        features['qty_exclamation_directory'] = path.count('!')
        features['qty_space_directory'] = path.count(' ')
        features['qty_tilde_directory'] = path.count('~')
        features['qty_comma_directory'] = path.count(',')
        features['qty_plus_directory'] = path.count('+')
        features['qty_asterisk_directory'] = path.count('*')
        features['qty_hashtag_directory'] = path.count('#')
        features['qty_dollar_directory'] = path.count('$')
        features['qty_percent_directory'] = path.count('%')
        
        # File counts
        features['qty_dot_file'] = path.split('/')[-1].count('.') if path else 0
        features['qty_hyphen_file'] = path.split('/')[-1].count('-') if path else 0
        features['qty_underline_file'] = path.split('/')[-1].count('_') if path else 0
        features['qty_slash_file'] = path.split('/')[-1].count('/') if path else 0
        features['qty_questionmark_file'] = path.split('/')[-1].count('?') if path else 0
        features['qty_equal_file'] = path.split('/')[-1].count('=') if path else 0
        features['qty_at_file'] = path.split('/')[-1].count('@') if path else 0
        features['qty_and_file'] = path.split('/')[-1].count('&') if path else 0
        features['qty_exclamation_file'] = path.split('/')[-1].count('!') if path else 0
        features['qty_space_file'] = path.split('/')[-1].count(' ') if path else 0
        features['qty_tilde_file'] = path.split('/')[-1].count('~') if path else 0
        features['qty_comma_file'] = path.split('/')[-1].count(',') if path else 0
        features['qty_plus_file'] = path.split('/')[-1].count('+') if path else 0
        features['qty_asterisk_file'] = path.split('/')[-1].count('*') if path else 0
        features['qty_hashtag_file'] = path.split('/')[-1].count('#') if path else 0
        features['qty_dollar_file'] = path.split('/')[-1].count('$') if path else 0
        features['qty_percent_file'] = path.split('/')[-1].count('%') if path else 0
        
        # Params counts
        features['qty_dot_params'] = query.count('.')
        features['qty_hyphen_params'] = query.count('-')
        features['qty_underline_params'] = query.count('_')
        features['qty_slash_params'] = query.count('/')
        features['qty_questionmark_params'] = query.count('?')
        features['qty_equal_params'] = query.count('=')
        features['qty_at_params'] = query.count('@')
        features['qty_and_params'] = query.count('&')
        features['qty_exclamation_params'] = query.count('!')
        features['qty_space_params'] = query.count(' ')
        features['qty_tilde_params'] = query.count('~')
        features['qty_comma_params'] = query.count(',')
        features['qty_plus_params'] = query.count('+')
        features['qty_asterisk_params'] = query.count('*')
        features['qty_hashtag_params'] = query.count('#')
        features['qty_dollar_params'] = query.count('$')
        features['qty_percent_params'] = query.count('%')
        
        # Length features
        features['length_domain'] = len(domain)
        features['length_path'] = len(path)
        features['length_query'] = len(query)
        
        # Special features
        features['having_IP_Address'] = 1 if re.search(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', url) else -1
        features['having_At_Symbol'] = 1 if '@' in url else -1
        features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
        features['url_shortened'] = 1 if any(s in domain for s in ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly']) else 0
        features['double_slash_redirecting'] = 1 if '//' in path else -1
        features['Prefix_Suffix'] = 1 if '-' in domain else -1
        features['qty_subdomain'] = domain.count('.') - 1 if domain else 0
        
        # Google index (simulated)
        features['url_google_index'] = 1
        features['domain_google_index'] = 1
        
        # Time response (simulated)
        features['time_response'] = 100
        features['time_domain_activation'] = 1000
        features['time_domain_expiration'] = 10000
        
        # DNS features (simulated)
        features['qty_ip_resolved'] = 1
        features['qty_nameservers'] = 2
        features['qty_mx_servers'] = 1
        features['ttl_hostname'] = 1000
        
        # Redirects
        features['qty_redirects'] = 0
        
    except Exception as e:
        st.warning(f"Error extracting some features: {e}")
    
    return features



url_input = st.text_input(
    "Enter Website URL",
    placeholder="https://google.com",
    help="Type or paste a URL to check"
)

if st.button(" Check Website", type="primary"):
    
    if not url_input:
        st.warning(" Please enter a URL")
    else:
        try:
            # Add http:// if not present
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            with st.spinner(" Analyzing website..."):
                # Get ALL features
                features_dict = extract_all_features(url_input)
                
                # Create input array
                input_df = pd.DataFrame([features_dict])[feature_names]
                
                # Scale and predict
                input_scaled = scaler.transform(input_df)
                prediction = model.predict(input_scaled)
                probability = model.predict_proba(input_scaled)[0]
            
            # Show result
            st.markdown("---")
            
            if prediction[0] == 1:
                st.error(" **PHISHING DETECTED!**")
                st.warning(f" This website appears to be a PHISHING site")
                col1, col2 = st.columns(2)
                col1.metric("Phishing Confidence", f"{probability[1]*100:.1f}%")
                col2.metric("Safety Confidence", f"{probability[0]*100:.1f}%")
            else:
                st.success(" **SAFE WEBSITE!**")
                st.success(f" This website appears to be LEGITIMATE")
                col1, col2 = st.columns(2)
                col1.metric("Safety Confidence", f"{probability[0]*100:.1f}%")
                col2.metric("Phishing Confidence", f"{probability[1]*100:.1f}%")
            
            st.caption(f"Analyzed: {url_input}")
            
        except Exception as e:
            st.error(f" Error: {e}")
            st.info("Please check the URL and try again")

# Footer
st.markdown("---")
st.caption("Phishing Detection using Machine Learning | Trained on 111 features")
