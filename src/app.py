from flask import Flask, request, Response
from flask_cors import CORS
from model.classify import email_body_classifier
import os
import requests
import config
import json
import re
import base64
from collections import defaultdict

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

################ for finding look-alikes #################
LOOK_ALIKES: str = ""
with open(f"{CURRENT_DIR}/look-alikes.txt", "r", encoding="utf-8") as file:
    LOOK_ALIKES = file.read()
    LOOK_ALIKES = LOOK_ALIKES.replace("\n", "")
###########################################################

app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})


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
        f"https://www.virustotal.com/api/v3/files/{hash}", headers={"x-apikey": config.API_KEY}).json()
    results = results["data"]["attributes"]

    # get category
    stats = results["last_analysis_stats"]
    possibilities = {"harmless": stats["harmless"], "malicious": stats["malicious"],
                     "suspicious": stats["suspicious"], "undetected": stats["undetected"]}
    category = max(possibilities, key=possibilities.get)

    data: dict = {
        "result": category,
        "user_votes": results["total_votes"]["malicious"]
    }
    d = json.dumps(data)

    response = Response(d)
    response.headers["Content-Type"] = "application/json"
    return response


@app.post("/find-bad-urls")
def find_bad_urls():
    # parse urls
    email_body = request.data.decode("utf-8")
    urls: list[str] = re.findall(
        "(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})", email_body)

    if len(urls) == 0:
        return ""

    categories: list = []

    # scan every url
    for url in urls:
        url_id = base64.urlsafe_b64encode(
            url.encode()).decode().strip("=")
        result = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": config.API_KEY}).json()
        try:
            result = result["data"]["attributes"]
            category = max(result["last_analysis_stats"],
                           key=result["last_analysis_stats"].get)
            categories.append(category)
        except:
            # wasn't scanned by VirusTotal
            categories.append("unscanned")

    data = defaultdict(list)
    data["urls"] = urls
    data["categories"] = categories
    d = json.dumps(data)

    response = Response(d)
    response.headers["Content-Type"] = "application/json"
    return response
