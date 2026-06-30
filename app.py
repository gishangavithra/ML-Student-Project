
import streamlit as st
import pickle
import numpy as np
import pandas as pd
import joblib

# Set page configuration
st.set_page_config(page_title="Phishing Website Detector", layout="wide")

# Page title and description
st.title(" Phishing Website Detector")
st.markdown("""
###  Detect if a website is legitimate or a phishing site
Enter the website features below and click **Check Website** to get a prediction.
""")

# Load the model, scaler, and feature names
@st.cache_resource
def load_model():
    try:
        model = joblib.load('model.pkl')
        scaler = joblib.load('scaler.pkl')
        feature_names = pickle.load(open('feature_names.pkl', 'rb'))
        return model, scaler, feature_names
    except Exception as e:
        st.error(f" Error loading model files: {e}")
        st.stop()

try:
    model, scaler, feature_names = load_model()
    st.success(f" Model loaded successfully! (Trained on {len(feature_names)} features)")
except Exception as e:
    st.error(f" Error loading model: {e}")
    st.stop()

# Create input fields
st.subheader(" Enter Website Features")

# Create columns for better layout
num_cols = 4
cols = st.columns(num_cols)

# Dictionary to store user inputs
user_inputs = {}

# Create input for each feature
for idx, feature in enumerate(feature_names):
    col_idx = idx % num_cols
    with cols[col_idx]:
        # Display feature name nicely
        display_name = feature.replace('_', ' ').title()
        user_inputs[feature] = st.number_input(
            display_name,
            value=0,
            step=1,
            key=f"input_{idx}",
            help=f"Enter value for {display_name}"
        )

# Predict button
st.markdown("---")
col1, col2, col3 = st.columns([1, 1, 1])
with col2:
    predict_button = st.button(" Check Website", type="primary", use_container_width=True)

if predict_button:
    try:
        # Create DataFrame with all features in correct order
        input_df = pd.DataFrame([user_inputs])[feature_names]
        
        # Scale the inputs
        input_scaled = scaler.transform(input_df)
        
        # Make prediction
        prediction = model.predict(input_scaled)
        probability = model.predict_proba(input_scaled)[0]
        
        # Display results
        st.markdown("---")
        st.subheader(" Prediction Result")
        
        # Create result cards
        col1, col2 = st.columns(2)
        
        if prediction[0] == 1:
            with col1:
                st.error(" **PHISHING DETECTED!**")
                st.warning(f" Confidence: {probability[1]*100:.1f}%")
                st.info("This website shows signs of being a phishing site.")
        else:
            with col1:
                st.success(" **SAFE WEBSITE!**")
                st.success(f" Confidence: {probability[0]*100:.1f}%")
                st.info("This website appears to be legitimate.")
        
        # Show probability distribution
        with col2:
            st.metric("Probability of being Phishing", f"{probability[1]*100:.1f}%")
            st.metric("Probability of being Legitimate", f"{probability[0]*100:.1f}%")
        
        # Show feature contribution (optional)
        st.subheader(" Feature Analysis")
        st.info("The model analyzed all features to make this prediction.")
        
    except Exception as e:
        st.error(f" Error making prediction: {e}")
        st.info("Please make sure all fields are filled correctly.")

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #666;">
    <p>Built with  using Streamlit and Random Forest Classifier</p>
    <p>Model Accuracy: 97%</p>
</div>
""", unsafe_allow_html=True)
