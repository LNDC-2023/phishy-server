from flask import Flask, request, Response, render_template
from flask_cors import CORS
from model.classify import email_body_classifier
import os
import requests
import config
import json
import re
import base64
from collections import defaultdict
import pandas as pd
from flask_httpauth import HTTPBasicAuth
from werkzeug.security import check_password_hash, generate_password_hash

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

################ for finding look-alikes #################
LOOK_ALIKES: str = ""
with open(f"{CURRENT_DIR}/look-alikes.txt", "r", encoding="utf-8") as file:
    LOOK_ALIKES = file.read()
    LOOK_ALIKES = LOOK_ALIKES.replace("\n", "")
###########################################################

app = Flask(__name__)
CORS(app, resources={r"*": {"origins": "*"}})
auth = HTTPBasicAuth()

ADMIN_PASSWORD = generate_password_hash(config.ADMIN_PASSWORD)


@auth.verify_password
def verify_password(username, password):
    if username == "admin" and check_password_hash(ADMIN_PASSWORD, password):
        return username

##### report frontend and backend #########################


REPORTED_FILE = f"{CURRENT_DIR}/reported.json"


@app.route("/")
@auth.login_required
def review_reports():
    with open(REPORTED_FILE, "r") as file:
        content = file.read()
        data = json.loads(content)
    return render_template("index.html", data=data)


def remove_entry_from_json(i: int):
    with open(REPORTED_FILE, "r") as file:
        old: list = json.loads(file.read())

    with open(REPORTED_FILE, "w") as file:
        del old[i]
        new = json.dumps(old)
        file.write(new)


@app.post("/reject-mail")
def reject_mail():
    try:
        i = int(request.data.decode("utf-8"))
    except:
        return "Failed", 500

    remove_entry_from_json(i)


@app.post("/accept-mail")
def accept_mail():
    try:
        i = int(request.data.decode("utf-8"))
    except:
        return "Failed", 500

    with open(REPORTED_FILE, "r") as file:
        data = json.loads(file.read())[i]
        email_text = data["Text"]
        email_type = data["Type"]

    remove_entry_from_json(i)

    # add to dataset
    df: pd.DataFrame = pd.read_csv(f"{CURRENT_DIR}/model/phishing_data_by_type.csv")
    df.loc[len(df.index)] = [email_text, email_type]

    return "Success", 200


@app.post("/report-mail")
def report_mail():
    email_body: str = request.data.decode("utf-8")
    type: str = "Phishing Email"

    data: dict = {
        "Text": email_body,
        "Type": type
    }

    # temporarily save to reported.json until review
    with open(REPORTED_FILE, "r") as file:
        old: list = json.loads(file.read())
        old.append(data)

    with open(REPORTED_FILE, "w") as file:
        new = json.dumps(old)
        file.write(new)

    return "Success", 200


###########################################################

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
        f"https: //www.virustotal.com/api/v3/files/{hash}", headers={"x-apikey": config.API_KEY}).json()
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
        r"(https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|www\.[a-zA-Z0-9][a-zA-Z0-9-]+[a-zA-Z0-9]\.[^\s]{2,}|https?:\/\/(?:www\.|(?!www))[a-zA-Z0-9]+\.[^\s]{2,}|www\.[a-zA-Z0-9]+\.[^\s]{2,})", email_body)

    if len(urls) == 0:
        return ""

    categories: list = []

    # scan every url
    for url in urls:
        url_id = base64.urlsafe_b64encode(
            url.encode()).decode().strip("=")
        result = requests.get(
            f"https: //www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": config.API_KEY}).json()
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
