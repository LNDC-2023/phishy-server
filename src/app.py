from flask import Flask, request
from model.classify import email_body_classifier

app = Flask(__name__)


@app.post("/email-body-classification")
def classify_email_body():
    email_body: str = request.data.decode("utf-8")
    prediction: str = email_body_classifier.predict(email_body)
    return prediction
