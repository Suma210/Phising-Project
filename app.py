#importing required libraries

from flask import Flask, request, render_template
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        url = request.form["url"].strip()

        if url.startswith("http://"):
            url = "https://" + url[len("http://"):]
        elif not url.startswith("https://"):
            url = "https://" + url

        print("Submitted URL:", repr(request.form["url"]))
        print("URL after normalization:", repr(url))

        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)

        prediction = int(gbc.predict(x)[0])

        print("URL:", url)
        print("Features:", x.tolist())
        print("Prediction:", prediction)
        print("Probabilities:", gbc.predict_proba(x)[0])
        probabilities = gbc.predict_proba(x)[0]

        # Explicitly map probabilities to their class labels.
        probability_by_class = dict(zip(gbc.classes_, probabilities))
        phishing_probability = float(probability_by_class[-1])
        legitimate_probability = float(probability_by_class[1])

        return render_template(
            "index.html",
            url=url,
            xx=legitimate_probability,
            prediction=prediction,
            phishing_probability=phishing_probability,
        )

    return render_template("index.html", xx=-1)



if __name__ == "__main__":
    app.run(debug=True)