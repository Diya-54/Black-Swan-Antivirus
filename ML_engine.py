import math
import numpy as np
import pandas as pd
from datetime import datetime
import joblib
import warnings

model = joblib.load("/home/diya/antivirusproject/Black-Swan/antivirus_model.pkl")

# ── If your model is loaded elsewhere, import/pass it in. ──────────────────
# This file assumes `model` is loaded in gui_new.py and passed to run_ml_scan().

def calculate_entropy(data):
    if not data:
        return 0
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    entropy = 0
    for count in byte_counts:
        if count == 0:
            continue
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy / 8  # normalize between 0 and 1


def extract_features_single_file(file_path):
    with open(file_path, 'rb') as f:
        content = f.read()
    entropy = calculate_entropy(content)
    size = len(content)
    byte_hist = [0] * 256
    for byte in content:
        byte_hist[byte] += 1
    byte_hist = [x / size for x in byte_hist]
    return [entropy, size] + byte_hist


def ml_yara_rules(features):
    entropy, size, *byte_hist = features
    triggered = []
    if entropy > 0.94:
        triggered.append("High Entropy")
    if size > 1_000_000:
        triggered.append("Large File Size")
    if size > 1024 and entropy < 0.8 and max(byte_hist) > 0.3:
        triggered.append("Suspicious Byte Pattern")
    accuracy = 0.96  # from your notebook
    return triggered, accuracy


def run_ml_scan(file_path, output_text):
    try:
        features = extract_features_single_file(file_path)

        # ✅ Use exact feature names from model, wrapped in DataFrame
        features_df = pd.DataFrame([features], columns=list(model.feature_names_in_))

        with warnings.catch_warnings():
            warnings.simplefilter("ignore")  # ✅ suppress any residual warnings
            prediction = model.predict(features_df)[0]

        if prediction == 1:
            output_text.insert("end", "\n⚠️ [ML] Warning: File is classified as MALICIOUS.\n")
        else:
            output_text.insert("end", "\n✅ [ML] Safe: File is classified as BENIGN.\n")

        try:
            if hasattr(model, 'predict_proba'):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore")  # ✅ suppress here too
                    proba = model.predict_proba(features_df)[0]
                malicious_prob, benign_prob = proba[1], proba[0]
                output_text.insert("end", f"\n[Confidence] Malicious: {malicious_prob*100:.2f}% | Benign: {benign_prob*100:.2f}%\n")
                output_text.insert("end", f"[Confidence] Primary prediction confidence: {max(proba)*100:.2f}%\n")
            else:
                output_text.insert("end", "\n[Confidence] Model does not support probability predictions.\n")
        except Exception as e:
            output_text.insert("end", f"\n[Confidence] Error calculating probability: {str(e)}\n")

        rules_flagged, accuracy = ml_yara_rules(features)
        if rules_flagged:
            output_text.insert("end", f"\n[ML-YARA] Suspicious Rules Triggered: {', '.join(rules_flagged)}\n")
        output_text.insert("end", f"\n[ML-YARA] Model Accuracy: {accuracy*100:.2f}%\n")

        with open("ml_yara_log.txt", "a") as log:
            log.write(f"{file_path} -- Rules: {', '.join(rules_flagged)} -- Time: {datetime.now()}\n")

    except Exception as e:
        import traceback
        output_text.insert("end", f"\n[ML] Feature extraction/prediction failed: {str(e)}\n")
        output_text.insert("end", f"\n[ML] Traceback: {traceback.format_exc()}\n")
