import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.metrics import accuracy_score
import joblib
import os

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))


class EmailBodyClassifier:
    def __init__(self) -> None:
        # prepare datasetb & data
        df: pd.DataFrame = pd.read_csv(f"{CURRENT_DIR}/Phishing_Email.csv")
        df = df.dropna()

        # downsampling, so there are the same amount of phishing and safe emails
        safe_emails = df[df["Email Type"] == "Safe Email"]
        phishing_emails = df[df["Email Type"] == "Phishing Email"]
        safe_emails = safe_emails.sample(phishing_emails.shape[0])

        data = pd.concat([safe_emails, phishing_emails], ignore_index=True)
        self.X = data["Email Text"].values
        self.y = data["Email Type"].values

    def train(self, test_size=0.2, n_estimators=100) -> None:
        X_train, self.X_test, y_train, self.y_test = train_test_split(
            self.X, self.y, test_size=test_size)

        self.clf = Pipeline([("tfidf", TfidfVectorizer(
        )), ("classifier", RandomForestClassifier(n_estimators=n_estimators))])

        self.clf.fit(X_train, y_train)

    def test(self) -> float:
        y_pred = self.clf.predict(self.X_test)
        score = accuracy_score(self.y_test, y_pred)
        return score

    def predict(self, email_body: str) -> str:
        predicted = self.clf.predict([email_body])
        return predicted[0]

################################################################


email_body_classifier: EmailBodyClassifier = None  # for external usage
clf_path: str = f"{CURRENT_DIR}/emailbodyclf.joblib"

if os.path.exists(clf_path):
    email_body_classifier = joblib.load(clf_path)
else:
    email_body_classifier = EmailBodyClassifier()
    email_body_classifier.train(test_size=None, n_estimators=100)
    joblib.dump(email_body_classifier, clf_path, compress=True)
