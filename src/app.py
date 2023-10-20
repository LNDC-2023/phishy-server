from flask import Flask, request, Response
from model.classify import email_body_classifier
import os
import requests
import config
import json

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

################ for finding look-alikes #################
LOOK_ALIKES: str = ""
with open(f"{CURRENT_DIR}/look-alikes.txt", "r", encoding="utf-8") as file:
    LOOK_ALIKES = file.read()
    LOOK_ALIKES = LOOK_ALIKES.replace("\n", "")
###########################################################

app = Flask(__name__)


@app.post("/email-body-classification")
def classify_email_body():
    email_body: str = request.data.decode("utf-8")
    prediction: str = email_body_classifier.predict(email_body)
    return prediction


@app.post("/find-look-alikes")
def find_look_alikes():
    content: str = request.data.decode("unicode-escape")
    print(content)
    for letter in content:
        if letter in LOOK_ALIKES:
            return "true"
    return "false"


@app.post("/scan-file-hash")
def scan_file_hash():
    hash = request.data.decode("utf-8")
    results = requests.get(
        f"https://www.virustotal.com/api/v3/files/{hash}", headers={"x-apikey": config.API_KEY})
    results = json.loads(results)

    data: dict = {
        "result": results["sandbox_verdicts"]["category"],
        "confidence": results["sandbox_verdicts"]["confidence"],
        "user_votes": results["total_votes"]["malicious"]
    }
    d = json.dumps(data)

    response = Response(d)
    response.headers["Content-Type"] = "application/json"
    return response
