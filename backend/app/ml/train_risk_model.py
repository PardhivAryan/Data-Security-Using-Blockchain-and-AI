import os
import random
import pickle

from sklearn.linear_model import LogisticRegression

from app.core.config import settings


COLUMNS = ["failed_auth_10m", "password_failed_10m", "denied_access_1h", "tamper_24h", "new_device_24h"]


def make_synthetic_row():
    failed = max(0, int(random.gauss(1, 2)))
    pwfail = max(0, int(random.gauss(0, 2)))
    denied = max(0, int(random.gauss(1, 3)))
    tamper = 1 if random.random() < 0.03 else 0
    new_device = 1 if random.random() < 0.10 else 0

    risk = 0
    if tamper == 1:
        risk = 1
    elif pwfail >= 2:
        risk = 1
    elif failed >= 4 and (new_device == 1 or denied >= 3):
        risk = 1
    elif failed >= 7:
        risk = 1

    x = [failed, pwfail, denied, tamper, new_device]
    y = risk
    return x, y


def train():
    X, Y = [], []
    for _ in range(9000):
        x, y = make_synthetic_row()
        X.append(x)
        Y.append(y)

    model = LogisticRegression(max_iter=250)
    model.fit(X, Y)

    os.makedirs(os.path.dirname(settings.risk_model_path), exist_ok=True)
    with open(settings.risk_model_path, "wb") as f:
        pickle.dump({"model": model, "columns": COLUMNS}, f)

    print("✅ Trained and saved:", settings.risk_model_path)


if __name__ == "__main__":
    train()