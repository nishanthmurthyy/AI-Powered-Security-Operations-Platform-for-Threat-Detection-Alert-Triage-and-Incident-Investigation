"""
====================================================================================
AI-Powered Security Operations Platform
Authentication Prediction Engine

File: authentication_predict.py

Description:
    Loads the trained Authentication XGBoost model and predicts whether
    an authentication event is Normal or Malicious.

Author: Sandra Jane F
====================================================================================
"""

import os
import logging
import warnings
import joblib
import pandas as pd
import numpy as np

warnings.filterwarnings("ignore")

# ==============================================================================
# PROJECT PATHS
# ==============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

MODEL_DIR = os.path.join(BASE_DIR, "models")

MODEL_PATH = os.path.join(
    MODEL_DIR,
    "authentication_xgboost_model.pkl"
)

FEATURE_PATH = os.path.join(
    MODEL_DIR,
    "authentication_feature_names.pkl"
)

LABEL_PATH = os.path.join(
    MODEL_DIR,
    "authentication_label_encoder.pkl"
)

# ==============================================================================
# LOGGING
# ==============================================================================

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logger = logging.getLogger(__name__)

# ==============================================================================
# LOAD MODEL
# ==============================================================================

logger.info("=" * 70)
logger.info("Loading Authentication XGBoost Model...")

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"Model not found:\n{MODEL_PATH}"
    )

model = joblib.load(MODEL_PATH)

logger.info("Model Loaded Successfully")

# ==============================================================================
# LOAD FEATURE NAMES
# ==============================================================================

if not os.path.exists(FEATURE_PATH):
    raise FileNotFoundError(
        f"Feature list not found:\n{FEATURE_PATH}"
    )

FEATURE_COLUMNS = joblib.load(FEATURE_PATH)

logger.info(f"Loaded {len(FEATURE_COLUMNS)} Features")

# ==============================================================================
# LOAD LABEL ENCODER
# ==============================================================================

if not os.path.exists(LABEL_PATH):
    raise FileNotFoundError(
        f"Label Encoder not found:\n{LABEL_PATH}"
    )

LABEL_ENCODER = joblib.load(LABEL_PATH)

logger.info("Label Encoder Loaded")

logger.info("=" * 70)

# ==============================================================================
# PREPROCESS INPUT EVENT
# ==============================================================================

def preprocess_event(event):
    """
    Converts an authentication event dictionary
    into a DataFrame compatible with the trained model.

    Parameters
    ----------
    event : dict

    Returns
    -------
    pandas.DataFrame
    """

    row = {}

    for feature in FEATURE_COLUMNS:

        if feature in event:
            row[feature] = event[feature]

        else:
            row[feature] = 0

    return pd.DataFrame([row])


# ==============================================================================
# VALIDATE INPUT
# ==============================================================================

def validate_event(event):
    """
    Validate authentication event.

    Returns
    -------
    bool
    """

    if not isinstance(event, dict):
        raise TypeError(
            "Authentication event must be a dictionary."
        )

    if len(event) == 0:
        raise ValueError(
            "Authentication event is empty."
        )

    return True


# ==============================================================================
# DISPLAY MODEL INFORMATION
# ==============================================================================

logger.info("Authentication Prediction Engine Ready")

logger.info(f"Model File      : {MODEL_PATH}")
logger.info(f"Feature Count   : {len(FEATURE_COLUMNS)}")

print("\nAuthentication Prediction Engine Initialized")
print(f"Loaded Features : {len(FEATURE_COLUMNS)}")
print("=" * 70)
# ==============================================================================
# PREDICT SINGLE AUTHENTICATION EVENT
# ==============================================================================

def predict_authentication(event):
    """
    Predict whether an authentication event is Normal or Malicious.

    Parameters
    ----------
    event : dict

    Returns
    -------
    dict
    """

    validate_event(event)

    input_df = preprocess_event(event)

    prediction = model.predict(input_df)[0]

    probabilities = model.predict_proba(input_df)[0]

    malicious_probability = float(probabilities[1])
    normal_probability = float(probabilities[0])

    confidence = float(np.max(probabilities))

    # --------------------------------------------------------------------------
    # Decode Prediction
    # --------------------------------------------------------------------------

    try:

        if hasattr(LABEL_ENCODER, "inverse_transform"):

            prediction_label = LABEL_ENCODER.inverse_transform(
                [prediction]
            )[0]

        else:

            prediction_label = LABEL_ENCODER[prediction]

    except Exception:

        prediction_label = (
            "redteam"
            if prediction == 1
            else "auth"
        )

    # --------------------------------------------------------------------------
    # Risk Level
    # --------------------------------------------------------------------------

    if malicious_probability >= 0.90:
        risk = "Critical"

    elif malicious_probability >= 0.75:
        risk = "High"

    elif malicious_probability >= 0.50:
        risk = "Medium"

    else:
        risk = "Low"

    # --------------------------------------------------------------------------
    # Result
    # --------------------------------------------------------------------------

    result = {

        "prediction": prediction_label,

        "prediction_code": int(prediction),

        "risk_level": risk,

        "malicious_probability": round(
            malicious_probability * 100,
            2
        ),

        "normal_probability": round(
            normal_probability * 100,
            2
        ),

        "confidence": round(
            confidence * 100,
            2
        )

    }

    return result


# ==============================================================================
# PREDICT MULTIPLE EVENTS
# ==============================================================================

def predict_batch(events):
    """
    Predict multiple authentication events.

    Parameters
    ----------
    events : list

    Returns
    -------
    list
    """

    if not isinstance(events, list):

        raise TypeError(
            "Input must be a list of dictionaries."
        )

    predictions = []

    logger.info(f"Predicting {len(events)} Events...")

    for index, event in enumerate(events):

        try:

            prediction = predict_authentication(event)

            prediction["event_number"] = index + 1

            predictions.append(prediction)

        except Exception as error:

            predictions.append({

                "event_number": index + 1,

                "prediction": "ERROR",

                "error": str(error)

            })

    logger.info("Batch Prediction Completed")

    return predictions


# ==============================================================================
# DISPLAY PREDICTION
# ==============================================================================

def print_prediction(result):
    """
    Nicely display prediction result.
    """

    print("\n" + "=" * 70)
    print("AUTHENTICATION PREDICTION")
    print("=" * 70)

    print(f"Prediction             : {result['prediction']}")
    print(f"Prediction Code        : {result['prediction_code']}")
    print(f"Risk Level             : {result['risk_level']}")
    print(f"Malicious Probability  : {result['malicious_probability']}%")
    print(f"Normal Probability     : {result['normal_probability']}%")
    print(f"Confidence             : {result['confidence']}%")

    print("=" * 70)


# ==============================================================================
# SAVE PREDICTION HISTORY
# ==============================================================================

def save_prediction(result, filename="authentication_predictions.csv"):
    """
    Save prediction to CSV.
    """

    filepath = os.path.join(BASE_DIR, "outputs", filename)

    df = pd.DataFrame([result])

    if os.path.exists(filepath):

        df.to_csv(
            filepath,
            mode="a",
            header=False,
            index=False
        )

    else:

        df.to_csv(
            filepath,
            index=False
        )

    logger.info(f"Prediction Saved -> {filepath}")
    # ==============================================================================
# TEST EVENT
# ==============================================================================

def test_prediction():
    """
    Test the Authentication Prediction Engine
    using a sample authentication event.
    """

    logger.info("=" * 70)
    logger.info("Running Authentication Prediction Test")

    sample_event = {

        "Hour": 13,
        "DayOfWeek": 2,
        "Weekend": 0,

        "IsAdmin": 1,
        "FailedLogin": 1,
        "FailedAttempts": 5,
        "NewDevice": 1,

        "SourceUser_enc": 120,
        "DestinationUser_enc": 120,

        "SourceComputer_enc": 45,
        "DestinationComputer_enc": 45,

        "AuthenticationType_enc": 1,
        "LogonType_enc": 3,
        "Activity_enc": 2,
        "Result_enc": 0

    }

    result = predict_authentication(sample_event)

    print_prediction(result)

    save_prediction(result)

    return result


# ==============================================================================
# PREDICT FROM DATAFRAME
# ==============================================================================

def predict_dataframe(df):
    """
    Predict every row of a dataframe.

    Parameters
    ----------
    df : pandas.DataFrame

    Returns
    -------
    pandas.DataFrame
    """

    predictions = []

    probabilities = []

    confidence_scores = []

    risk_levels = []

    logger.info(f"Predicting {len(df)} Records...")

    for _, row in df.iterrows():

        event = row.to_dict()

        result = predict_authentication(event)

        predictions.append(result["prediction"])

        probabilities.append(result["malicious_probability"])

        confidence_scores.append(result["confidence"])

        risk_levels.append(result["risk_level"])

    output = df.copy()

    output["Prediction"] = predictions
    output["MaliciousProbability"] = probabilities
    output["Confidence"] = confidence_scores
    output["RiskLevel"] = risk_levels

    return output


# ==============================================================================
# LOAD CSV AND PREDICT
# ==============================================================================

def predict_csv(csv_path):
    """
    Predict an entire CSV file.

    Parameters
    ----------
    csv_path : str

    Returns
    -------
    pandas.DataFrame
    """

    if not os.path.exists(csv_path):

        raise FileNotFoundError(csv_path)

    logger.info(f"Loading CSV : {csv_path}")

    df = pd.read_csv(csv_path)

    result_df = predict_dataframe(df)

    output_path = os.path.join(
        BASE_DIR,
        "outputs",
        "authentication_predictions.csv"
    )

    result_df.to_csv(
        output_path,
        index=False
    )

    logger.info(f"Predictions Saved : {output_path}")

    return result_df


# ==============================================================================
# MAIN
# ==============================================================================

def main():

    print("\n")
    print("=" * 70)
    print("AUTHENTICATION XGBOOST PREDICTION ENGINE")
    print("=" * 70)

    try:

        result = test_prediction()

        print("\nPrediction Completed Successfully.")

        print("\nSummary")

        print(f"Prediction             : {result['prediction']}")
        print(f"Risk Level             : {result['risk_level']}")
        print(f"Confidence             : {result['confidence']}%")

        print("\nSystem Status")

        print("Model Loaded               ✓")
        print("Feature Names Loaded       ✓")
        print("Prediction Engine Ready    ✓")

    except Exception as error:

        logger.exception(error)

        print("\nPrediction Failed")

        print(error)

    print("=" * 70)


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":

    main()