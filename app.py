import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
import socket
import whois
from datetime import datetime

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")

st.title("🌐 Phishing Website Detector")
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
    st.success("✅ ")
else:
    st.error("❌ ")
    st.stop()



def is_valid_domain(domain):
    """Check if domain exists and is valid"""
    try:
        # Check if domain has valid format
        if not domain or len(domain) < 3:
            return False, "Domain too short"
        
        # Must have a dot
        if '.' not in domain:
            return False, "Domain must have a dot (e.g., .com)"
        
        # Check for valid TLD (common ones)
        valid_tlds = ['.com', '.org', '.net', '.edu', '.gov', '.io', '.co', '.uk', '.de', '.fr', '.jp', '.au', '.ca', '.in']
        has_valid_tld = any(domain.endswith(tld) for tld in valid_tlds)
        
        if not has_valid_tld:
            return False, f"Unusual domain ending. Common TLDs: .com, .org, .net, .edu, .gov"
        
        # Check for suspicious patterns in domain
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP address
            r'[a-zA-Z0-9]{30,}',     # Very long subdomain
            r'\.{2,}',               # Double dots
            r'^[0-9]+',              # Starts with numbers
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return False, "Suspicious domain pattern detected"
        
        # Try to resolve domain (check if it exists)
        try:
            socket.gethostbyname(domain)
            return True, "Domain exists"
        except:
            return False, "Domain does not exist or cannot be resolved"
            
    except Exception as e:
        return False, f"Domain validation error: {e}"

def check_misspelled_domain(domain):
    """Check if domain looks like a misspelled famous domain"""
    famous_domains = [
        'google.com', 'facebook.com', 'youtube.com', 'amazon.com',
        'microsoft.com', 'apple.com', 'netflix.com', 'twitter.com',
        'instagram.com', 'linkedin.com', 'wikipedia.org', 'yahoo.com'
    ]
    
    for famous in famous_domains:
        # Check if domain is similar but not exactly the same
        if domain != famous:
            # Remove TLD and compare
            famous_base = famous.split('.')[0]
            domain_base = domain.split('.')[0]
            
            # Check for misspelling (typo)
            if len(domain_base) > 3 and len(famous_base) > 3:
                # If domain contains the famous name but with extra chars
                if famous_base in domain_base and domain != famous:
                    return True, f"Domain may be a misspelling of {famous}"
                
                # Levenshtein-like check (simple)
                if abs(len(domain_base) - len(famous_base)) <= 2:
                    matches = sum(1 for a, b in zip(domain_base, famous_base) if a == b)
                    if matches / max(len(domain_base), len(famous_base)) > 0.7:
                        return True, f"Domain may be a misspelling of {famous}"
    
    return False, ""



def extract_all_features(url):
    """Extract features from URL with better defaults"""
    
    features = {}
    for f in feature_names:
        features[f] = -1
    
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        
        parsed = urlparse(url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
        scheme = parsed.scheme
        
        # URL counts
        features['length_url'] = min(len(url), 1000)
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
        
        # Domain counts
        if domain:
            features['qty_dot_domain'] = min(domain.count('.'), 10)
            features['qty_hyphen_domain'] = min(domain.count('-'), 10)
            features['qty_underline_domain'] = min(domain.count('_'), 10)
            features['qty_slash_domain'] = min(domain.count('/'), 5)
            features['qty_questionmark_domain'] = min(domain.count('?'), 5)
            features['qty_equal_domain'] = min(domain.count('='), 5)
            features['qty_at_domain'] = min(domain.count('@'), 5)
            features['length_domain'] = min(len(domain), 100)
        
        # Directory counts
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
        
        # Query counts
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
        
        # Special features
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        features['having_IP_Address'] = 1 if re.search(ip_pattern, url) else -1
        features['having_At_Symbol'] = 1 if '@' in url else -1
        features['tls_ssl_certificate'] = 1 if scheme == 'https' else 0
        
        shorteners = ['bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly']
        features['url_shortened'] = 1 if any(s in domain for s in shorteners) else 0
        features['double_slash_redirecting'] = 1 if '//' in path and path.count('//') > 1 else -1
        features['Prefix_Suffix'] = 1 if '-' in domain else -1
        features['qty_subdomain'] = max(0, domain.count('.') - 1) if domain else 0
        
        # Default values
        features['url_google_index'] = 1
        features['domain_google_index'] = 1
        features['time_response'] = 50
        features['time_domain_activation'] = 500
        features['time_domain_expiration'] = 365
        features['qty_ip_resolved'] = 1
        features['qty_nameservers'] = 2
        features['qty_mx_servers'] = 1
        features['ttl_hostname'] = 86400
        features['qty_redirects'] = 0
        features['domain_age'] = 365
        features['whois_registered'] = 1
        features['whois_updated'] = 30
        features['ssl_valid'] = 1
        features['ssl_age'] = 365
        
    except Exception as e:
        pass
    
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

if st.button("🔍 Check Website", type="primary", use_container_width=True):
    
    url_to_check = st.session_state.url_input.strip()
    
    if not url_to_check:
        st.warning("⚠️ Please enter a URL")
    else:
        try:
            # Fix URL
            if not url_to_check.startswith(('http://', 'https://')):
                url_to_check = 'http://' + url_to_check
            
            # Remove duplicate protocols
            if url_to_check.count('://') > 1:
                first_protocol_end = url_to_check.find('://') + 3
                url_to_check = url_to_check[:first_protocol_end] + url_to_check[first_protocol_end:].replace('http://', '').replace('https://', '')
            
            parsed = urlparse(url_to_check)
            display_domain = parsed.netloc
            
          
            
            is_valid, validation_msg = is_valid_domain(display_domain)
            is_misspelled, misspell_msg = check_misspelled_domain(display_domain)
            
            st.markdown("---")
            st.caption(f" Analyzed: {display_domain}")
            
         
            
            # If domain doesn't exist or is misspelled, mark as PHISHING
            if not is_valid or is_misspelled:
                st.error("🚨 **PHISHING DETECTED!**")
                st.warning(f"⚠️ {display_domain} appears to be a PHISHING or FAKE website")
                
                if not is_valid:
                    st.error(f"❌ Domain Issue: {validation_msg}")
                
                if is_misspelled:
                    st.error(f"❌ Misspelling Detected: {misspell_msg}")
                
                st.info("💡 **Tip:** Always double-check the domain name. Phishing sites often use misspelled versions of real websites.")
                
                # Show fake domain warning
                st.warning("⚠️ **THIS IS A FAKE DOMAIN** - Do not enter any personal information!")
                
            else:
              
                
                with st.spinner(f"🔍 Analyzing {display_domain}..."):
                    features_dict = extract_all_features(url_to_check)
                    input_df = pd.DataFrame([features_dict])[feature_names]
                    
                    input_scaled = scaler.transform(input_df)
                    prediction = model.predict(input_scaled)
                    probability = model.predict_proba(input_scaled)[0]
                
                # Show ML results
                if prediction[0] == 1:
                    st.error("🚨 **PHISHING DETECTED!**")
                    st.warning(f"⚠️ {display_domain} appears to be a PHISHING site")
                    col1, col2 = st.columns(2)
                    col1.metric("⚠️ Phishing Confidence", f"{probability[1]*100:.1f}%")
                    col2.metric("✅ Legitimate Confidence", f"{probability[0]*100:.1f}%")
                else:
                    st.success("✅ **SAFE WEBSITE!**")
                    st.success(f"✅ {display_domain} appears to be LEGITIMATE")
                    col1, col2 = st.columns(2)
                    col1.metric("✅ Legitimate Confidence", f"{probability[0]*100:.1f}%")
                    col2.metric("⚠️ Phishing Confidence", f"{probability[1]*100:.1f}%")
                
                # Security tips for suspicious TLDs
                suspicious_tlds = ['.xyz', '.club', '.online', '.top', '.site', '.click', '.link', '.work', '.date']
                if any(display_domain.endswith(tld) for tld in suspicious_tlds):
                    st.info("⚠️ **Security Note:** Unusual domains (.xyz, .club, .online) are often used for phishing. Always verify carefully.")
            
        except Exception as e:
            st.error(f"❌ Error: {e}")

# Footer
st.markdown("---")
st.caption("S25021283 - Lokuwaduge Gishan Gavithra De Silva | COM763 - Advanced Machine Learning | Phishing Detection using ML")
