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
        df: pd.DataFrame = pd.read_csv(
            f"{CURRENT_DIR}/phishing_data_by_type.csv")
        df = df.dropna()
        df = df.drop("Subject", axis=1)

        for _, row in df.iterrows():
            if row["Type"] == "Fraud" or row["Type"] == "Phishing":
                row["Type"] = "Phishing"
            else:
                row["Type"] = "Safe"

        self.X = df["Text"].values
        self.y = df["Type"].values

    def train(self, test_size=0.2, n_estimators=100) -> None:

        if test_size == 0:
            X_train = self.X
            y_train = self.y
        else:
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


#email_body_classifier: EmailBodyClassifier = None  # for external usage
#clf_path: str = f"{CURRENT_DIR}/emailbodyclf.joblib"

#if os.path.exists(clf_path):
#    email_body_classifier = joblib.load(clf_path)
#else:
email_body_classifier = EmailBodyClassifier()
email_body_classifier.train(test_size=0, n_estimators=100)
#joblib.dump(email_body_classifier, f"{CURRENT_DIR}/emailbodyclf.joblib", compress=True)
