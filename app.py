from flask import Flask, render_template, request
import FeatureExtraction

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("home.html")

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/getURL', methods=['POST'])
def getURL():
    if request.method == 'POST':
        url = request.form['url']
        try:
            feature_extractor = FeatureExtraction.FeatureExtraction()
            features = feature_extractor.getFeatures(url)
            if features:
                predicted_value = custom_classifier(features)
                result = "Phishing" if predicted_value == 1 else "Legitimate"
                return render_template("result.html", url=url, result=result)
            else:
                return "Error: Unable to extract features."
        except Exception as e:
            return f"Error: {str(e)}"

def custom_classifier(features):
    if features['Having_IP'] == 1 or features['Having_@_symbol'] == 1 or features['Numbers_at_beginning'] == 1:
        return 1  # Phishing
    elif features['Protocol'] == 'http' or features['Google_index'] == 1:
        return 0
    elif features['HTTPS_token'] == 'https://|http://' or features['DNS_record'] == 1:
        return 1
    else:
        return 0  # Legitimate

if __name__ == "__main__":
    app.run(debug=True)
