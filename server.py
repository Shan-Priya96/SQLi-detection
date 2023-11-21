# Import necessary libraries
from flask import Flask, request, jsonify, render_template, redirect
import pandas as pd
import joblib  # for loading the model
import re

# Flask server setup
app = Flask(__name__)

# Load the pre-trained Random Forest model from the .pkl file
rf_classifier = joblib.load('finalized_model.pkl')
def count_dns_requests(text):
    return text.lower().count('dns')

# Function to check for the presence of out-of-band keywords
def contains_out_of_band_keywords(text):
    out_of_band_keywords = ['dns', 'http', 'ftp', 'udp']
    return any(keyword in text.lower() for keyword in out_of_band_keywords)
def contains_time_based_keywords(text):
    time_based_keywords =['SLEEP', 'WAITFOR DELAY', 'DBMS_LOCK.SLEEP', 'PG_SLEEP', 'BENCHMARK', 'IF','CASE']
    return any(keyword in text.lower() for keyword in time_based_keywords)
# Function to check for the presence of URLs or IP addresses
def contains_urls_or_ip_addresses(text):
    return bool(re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
# Helper function for feature extraction
def extract_features(text):
    return {
        'length': len(text),
        'special_chars': sum(c.isalnum() for c in text),
        'numeric_chars': sum(c.isdigit() for c in text),
        'uppercase_chars': sum(c.isupper() for c in text),
        'lowercase_chars': sum(c.islower() for c in text),
        'whitespace_chars': sum(c.isspace() for c in text),
        'dns_request_count': count_dns_requests(text),
        'contains_out_of_band_keywords': contains_out_of_band_keywords(text),
        'contains_urls_or_ip_addresses': contains_urls_or_ip_addresses(text),
        'contains_time_based_keywords': contains_time_based_keywords(text),
    }


# Function for SQL injection detection
def detect_sql_injection(username, password):
    # Feature extraction for username and password
    username_features = extract_features(username)
    password_features = extract_features(password)

    # Create a DataFrame with the features for username and password
    username_query_features = pd.DataFrame({f'{key}': value for key, value in username_features.items()}, index=[0])
    password_query_features = pd.DataFrame({f'{key}': value for key, value in password_features.items()}, index=[0])

    # Make predictions using the loaded model for username and password
    username_prediction = bool(rf_classifier.predict(username_query_features)[0])
    password_prediction = bool(rf_classifier.predict(password_query_features)[0])

    # Return flags indicating if the username and/or password are identified as potential SQL injections
    return username_prediction, password_prediction

# Flask endpoint for SQL injection detection
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/detect_sql_injection', methods=['POST'])
def detect_sql_injection_endpoint():
    username = request.form.get('username')
    password = request.form.get('password')

    # Call your SQL injection detection function
    is_username_sqli, is_password_sqli = detect_sql_injection(username, password)

    # Check if both username and password are safe
    if not is_username_sqli and not is_password_sqli:
        # Both are safe, redirect to home.php
        return render_template('home.html')

    # At least one is identified as potential SQL injection, render result.html
    return render_template('result.html', is_username_sqli=is_username_sqli, is_password_sqli=is_password_sqli)

# Run the Flask server
if __name__ == '__main__':
    app.run(host='localhost', port=5000)

