
import numpy as np
from feature import FeatureExtraction
from app import gbc

for url in [
    "https://www.google.com",
    "https://example.com",
]:
    print("\nURL:", url)

    features = FeatureExtraction(url).getFeaturesList()
    x = np.array(features).reshape(1, -1)

    print("Feature count:", x.shape[1])
    print("Features:", features)
    print("Predicted class:", gbc.predict(x)[0])
    print("Class order:", gbc.classes_)
    print("Probabilities:", gbc.predict_proba(x)[0])
