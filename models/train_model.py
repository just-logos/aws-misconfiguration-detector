import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import joblib

# Load training dataset
df = pd.read_csv('../data/scan_results.csv')

# Drop columns not used as features
df = df.drop(columns=['resource_name'])

# Convert label column to numerical value: compliant = 0, misconfigured = 1
df['label'] = df['label'].map({'compliant': 0, 'misconfigured': 1})

# One-hot encode the resource_type column into binary columns
df = pd.get_dummies(df, columns=['resource_type'], dtype=int)

# Split data into features (X) and labels (y)
X = df.drop(columns=['label'])
y = df['label']

# Split data into 80% training and 20% testing sets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train the Random Forest Classifier on the training data
model = RandomForestClassifier(random_state=42)
model.fit(X_train, y_train)

# Evaluate model accuracy on the test set
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
print(f"Model Accuracy: {accuracy * 100:.2f}%")

# Save the trained model to a file for later use
joblib.dump(model, '../models/model.pkl')
print("Model saved to models/model.pkl")