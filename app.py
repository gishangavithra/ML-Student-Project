import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib
import re
from urllib.parse import urlparse
import socket
from datetime import datetime

# Page setup
st.set_page_config(page_title="Phishing Detector", layout="centered")

st.title("🌐 Phishing Website Detector")
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
        if not domain or len(domain) < 3:
            return False, "Domain too short"
        
        if '.' not in domain:
            return False, "Domain must have a dot (e.g., .com)"
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r'\d+\.\d+\.\d+\.\d+',  # IP address
            r'\.{2,}',               # Double dots
            r'[a-zA-Z0-9]{50,}',     # Very long domain
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, domain):
                return False, "Suspicious domain pattern detected"
        
        # Check if domain resolves (exists)
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
        'instagram.com', 'linkedin.com', 'wikipedia.org', 'yahoo.com',
        'whatsapp.com', 'paypal.com', 'ebay.com', 'spotify.com'
    ]
    
    # Remove www. prefix if present
    domain_clean = domain.replace('www.', '')
    
    for famous in famous_domains:
        if domain_clean == famous:
            continue
        
        famous_base = famous.split('.')[0]
        domain_base = domain_clean.split('.')[0]
        
        # Check if domain contains the famous name with extra characters
        if famous_base in domain_base and domain_clean != famous:
            return True, f"⚠️ May be a fake version of {famous}"
        
        # Check for one-character typo
        if len(domain_base) > 3 and len(famous_base) > 3:
            diff = abs(len(domain_base) - len(famous_base))
            if diff <= 2:
                # Count matching characters
                matches = 0
                for i in range(min(len(domain_base), len(famous_base))):
                    if i < len(famous_base) and i < len(domain_base):
                        if domain_base[i] == famous_base[i]:
                            matches += 1
                match_ratio = matches / max(len(domain_base), len(famous_base))
                if match_ratio > 0.7 and domain_clean != famous:
                    return True, f"⚠️ May be a misspelling of {famous}"
    
    return False, ""

def check_suspicious_tld(domain):
    """Check for suspicious TLDs"""
    suspicious = [
        '.xyz', '.top', '.club', '.online', '.site', 
        '.click', '.link', '.work', '.date', '.download',
        '.review', '.trade', '.stream', '.gq', '.ml', '.cf'
    ]
    for tld in suspicious:
        if domain.endswith(tld):
            return True, f"⚠️ Unusual TLD '{tld}' - often used for phishing"
    return False, ""



def extract_all_features(url):
    """Extract features from URL"""
    
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
            is_suspicious_tld, tld_msg = check_suspicious_tld(display_domain)
            
            st.markdown("---")
            st.caption(f"📌 Analyzed: {display_domain}")
            
       
            
            # Count how many warning flags are triggered
            warning_count = 0
            warning_messages = []
            
            if not is_valid:
                warning_count += 1
                warning_messages.append(f"❌ {validation_msg}")
            
            if is_misspelled:
                warning_count += 1
                warning_messages.append(f"❌ {misspell_msg}")
            
            if is_suspicious_tld:
                warning_count += 1
                warning_messages.append(f"❌ {tld_msg}")
            
            # If any warnings, mark as PHISHING
            if warning_count > 0:
                st.error("🚨 **PHISHING DETECTED!**")
                st.warning(f"⚠️ {display_domain} appears to be a PHISHING or FAKE website")
                
                for msg in warning_messages:
                    st.error(msg)
                
                if not is_valid:
                    st.info("💡 **Tip:** The domain does not exist or cannot be resolved. This is a common sign of phishing.")
                
                if is_misspelled:
                    st.info("💡 **Tip:** Phishing sites often use misspelled versions of real websites. Always double-check the URL.")
                
                st.warning("⚠️ **DO NOT enter any personal information on this website!**")
                
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
                    st.info("💡 **Tip:** Phishing sites try to steal your personal information. Always verify the URL carefully.")
                else:
                    st.success("✅ **SAFE WEBSITE!**")
                    st.success(f"✅ {display_domain} appears to be LEGITIMATE")
                    col1, col2 = st.columns(2)
                    col1.metric("✅ Legitimate Confidence", f"{probability[0]*100:.1f}%")
                    col2.metric("⚠️ Phishing Confidence", f"{probability[1]*100:.1f}%")
            
        except Exception as e:
            st.error(f"❌ Error: {e}")

# Footer
st.markdown("---")
st.caption("S25021283 - Lokuwaduge Gishan Gavithra De Silva | COM763 - Advanced Machine Learning | Phishing Detection using ML")
