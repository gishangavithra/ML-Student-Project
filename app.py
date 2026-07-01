import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")

# Title
st.title(" Phishing Website Detector")

# Simple description
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
except:
    st.error(" Error loading model")
    st.stop()



def get_features_from_url(url):
    """Extract features from URL - simple version"""
    
    # Start with all zeros
    features = {f: 0 for f in feature_names}
    
    # Parse URL
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # Basic URL features (only the most important ones)
    features['length_url'] = len(url)
    features['qty_dot_url'] = url.count('.')
    features['qty_hyphen_url'] = url.count('-')
    features['qty_slash_url'] = url.count('/')
    features['qty_questionmark_url'] = url.count('?')
    features['qty_equal_url'] = url.count('=')
    features['qty_at_url'] = url.count('@')
    features['qty_and_url'] = url.count('&')
    
    # Domain features
    features['qty_dot_domain'] = domain.count('.')
    features['qty_hyphen_domain'] = domain.count('-')
    features['length_domain'] = len(domain)
    
    # Check for IP address
    ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    features['having_IP_Address'] = 1 if re.search(ip_pattern, url) else -1
    
    # Check for @ symbol
    features['having_At_Symbol'] = 1 if '@' in url else -1
    
    # Check for HTTPS
    features['tls_ssl_certificate'] = 1 if parsed.scheme == 'https' else 0
    
    # Check for URL shorteners
    shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly']
    features['url_shortened'] = 1 if any(s in domain for s in shorteners) else 0
    
    # Check for double slash in path
    features['double_slash_redirecting'] = 1 if '//' in path else -1
    
    # Check for prefix/suffix
    features['Prefix_Suffix'] = 1 if '-' in domain else -1
    
    # Subdomain count
    features['qty_subdomain'] = domain.count('.') - 1 if domain else 0
    
    # Path length
    features['length_path'] = len(path)
    
    # Query length
    features['length_query'] = len(parsed.query)
    
    return features


# Text input for URL
url_input = st.text_input(
    "Enter Website URL",
    placeholder="https://example.com",
    help="Type or paste a URL to check"
)

# Check button
if st.button(" Check Website", type="primary"):
    
    if not url_input:
        st.warning(" Please enter a URL")
    else:
        try:
            # Add http:// if not present
            if not url_input.startswith(('http://', 'https://')):
                url_input = 'http://' + url_input
            
            # Get features
            features_dict = get_features_from_url(url_input)
            
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
                st.metric("Phishing Confidence", f"{probability[1]*100:.1f}%")
            else:
                st.success(" **SAFE WEBSITE!**")
                st.success(f" This website appears to be LEGITIMATE")
                st.metric("Safety Confidence", f"{probability[0]*100:.1f}%")
            
            # Show analyzed URL
            st.caption(f"Analyzed: {url_input}")
            
        except Exception as e:
            st.error(f" Error: {e}")
            st.info("Please check the URL and try again")

# Footer
st.markdown("---")
st.caption("Phishing Detection using Machine Learning")
