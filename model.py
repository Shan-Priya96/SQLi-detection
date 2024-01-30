import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import pickle
import re


def count_dns_requests(text):
    return text.lower().count('dns')

def contains_out_of_band_keywords(text):
    out_of_band_keywords = ['dns', 'http', 'ftp', 'udp']
    return any(keyword in text.lower() for keyword in out_of_band_keywords)

def contains_urls_or_ip_addresses(text):
    return bool(re.search(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text))
# print(contains_urls_or_ip_addresses("http://www.google.com"))
def contains_time_based_keywords(text):
    time_based_keywords =['SLEEP', 'WAITFOR DELAY', 'DBMS_LOCK.SLEEP', 'PG_SLEEP', 'BENCHMARK', 'IF','CASE']
    return any(keyword in text.lower() for keyword in time_based_keywords)
def count_semicolons(sentence):
    return sentence.count(';')

# Function to count the number of opening brackets in a sentence
def count_opening_brackets(sentence):
    return sentence.count('(')

# Function to count the number of closing brackets in a sentence
def count_closing_brackets(sentence):
    return sentence.count(')')

df = pd.read_csv('dataset1.csv')
df['Sentence']=df["Sentence"].astype(str)
df['Label']=df["Label"].astype(int)

df['length'] = df['Sentence'].apply(len)
df['special_chars'] = df['Sentence'].apply(lambda x: sum(c.isalnum() for c in x))
df['numeric_chars'] = df['Sentence'].apply(lambda x: sum(c.isdigit() for c in x))
df['num_semicolons'] = df['Sentence'].apply(count_semicolons)
df['num_opening_brackets'] = df['Sentence'].apply(count_opening_brackets)
df['num_closing_brackets'] = df['Sentence'].apply(count_closing_brackets)
df['whitespace_chars'] = df['Sentence'].apply(lambda x: sum(c.isspace() for c in x))
df['dns_request_count'] = df['Sentence'].apply(count_dns_requests)
df['contains_out_of_band_keywords'] = df['Sentence'].apply(contains_out_of_band_keywords)
df['contains_urls_or_ip_addresses'] = df['Sentence'].apply(contains_urls_or_ip_addresses)
df['contains_time_based_keywords'] = df['Sentence'].apply(contains_time_based_keywords)



X = df.drop(['Sentence', 'Label'], axis=1)  # Assuming 'Label' is the column indicating benign/malicious (0/1)
y = df['Label']


X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

from sklearn.utils.class_weight import compute_class_weight

# class_weights = compute_class_weight('balanced', classes=[0, 1], y=y_train)

# # Assign more weight to the last three features
# feature_weights = {
#     'length': 1.0,
#     'special_chars': 2.0,
#     'numeric_chars': 1.0,
#     'uppercase_chars': 1.0,
#     'lowercase_chars': 1.0,
#     'whitespace_chars': 1.0,
#     'dns_request_count': 2.0,  
#     'contains_out_of_band_keywords': 2.0,  
#     'contains_urls_or_ip_addresses': 2.0  
# }

# # Multiply the class weights by the feature weights
# class_weight_dict = {
#     0: class_weights[0],
#     1: class_weights[1] * sum(feature_weights.values()) / len(feature_weights)
# }

rf_classifier = RandomForestClassifier(n_estimators=100, random_state=42)



rf_classifier.fit(X_train, y_train)
filename = 'finalized_model.pkl'
pickle.dump(rf_classifier, open(filename, 'wb'))

y_pred = rf_classifier.predict(X_test)

accuracy = accuracy_score(y_test, y_pred)
conf_matrix = confusion_matrix(y_test, y_pred)
classification_rep = classification_report(y_test, y_pred)

print(f'Accuracy: {accuracy}')