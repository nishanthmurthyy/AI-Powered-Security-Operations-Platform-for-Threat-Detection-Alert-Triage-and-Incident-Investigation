"""
====================================================================================
AI-Powered Security Operations Platform

Windows Authentication Event Monitor

File : windows_event_monitor.py

Description:
    Reads Windows Authentication Events,
    extracts ML features,
    sends them to authentication_predict.py,
    and generates authentication alerts.

Author : Sandra Jane F
====================================================================================
"""

import os
import time
import logging
import warnings
from datetime import datetime

import pandas as pd

try:
    import win32evtlog
    WINDOWS_AVAILABLE = True
except ImportError:
    WINDOWS_AVAILABLE = False

from authentication_predict import predict_authentication

warnings.filterwarnings("ignore")

# ==============================================================================
# PROJECT PATHS
# ==============================================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

OUTPUT_DIR = os.path.join(BASE_DIR, "outputs")

os.makedirs(OUTPUT_DIR, exist_ok=True)

ALERT_FILE = os.path.join(
    OUTPUT_DIR,
    "windows_event_alerts.csv"
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
# WINDOWS SECURITY EVENT IDS
# ==============================================================================

EVENT_NAMES = {

    4624: "Successful Logon",

    4625: "Failed Logon",

    4648: "Explicit Credentials",

    4672: "Admin Logon",

    4768: "Kerberos TGT",

    4769: "Kerberos Service Ticket",

    4776: "NTLM Authentication"

}

# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def weekend_flag(day):

    return 1 if day >= 5 else 0


def admin_flag(event_id):

    return 1 if event_id == 4672 else 0


def failed_login(event_id):

    return 1 if event_id == 4625 else 0


def authentication_type(event_id):

    if event_id in [4768, 4769]:
        return 1

    if event_id == 4776:
        return 3

    return 0


def logon_type(event_id):

    if event_id == 4624:
        return 3

    if event_id == 4625:
        return 3

    return 0


def activity_type(event_id):

    if event_id == 4624:
        return 2

    if event_id == 4625:
        return 2

    return 0


def result_code(event_id):

    if event_id == 4625:
        return 0

    return 1


# ==============================================================================
# SIMPLE HASH ENCODER
# ==============================================================================

def encode(value):

    if value is None:
        return 0

    return abs(hash(str(value))) % 1000


# ==============================================================================
# FEATURE EXTRACTION
# ==============================================================================

def extract_features(event):

    """
    Converts a Windows Security Event
    into ML features.
    """

    event_time = event.get(
        "TimeGenerated",
        datetime.now()
    )

    hour = event_time.hour

    day = event_time.weekday()

    event_id = event.get("EventID", 0)

    username = event.get(
        "User",
        "Unknown"
    )

    computer = event.get(
        "Computer",
        "Unknown"
    )

    features = {

        "Hour": hour,

        "DayOfWeek": day,

        "Weekend": weekend_flag(day),

        "IsAdmin": admin_flag(event_id),

        "FailedLogin": failed_login(event_id),

        "FailedAttempts": event.get(
            "FailedAttempts",
            0
        ),

        "NewDevice": event.get(
            "NewDevice",
            0
        ),

        "SourceUser_enc":
            encode(username),

        "DestinationUser_enc":
            encode(username),

        "SourceComputer_enc":
            encode(computer),

        "DestinationComputer_enc":
            encode(computer),

        "AuthenticationType_enc":
            authentication_type(event_id),

        "LogonType_enc":
            logon_type(event_id),

        "Activity_enc":
            activity_type(event_id),

        "Result_enc":
            result_code(event_id)

    }

    return features


# ==============================================================================
# WINDOWS EVENT READER
# ==============================================================================

def read_windows_events():

    """
    Reads recent Windows Security Events.

    Returns
    -------
    list
    """

    if not WINDOWS_AVAILABLE:

        logger.warning(
            "pywin32 not installed. "
            "Running in simulation mode."
        )

        return []

    server = "localhost"

    logtype = "Security"

    handle = win32evtlog.OpenEventLog(
        server,
        logtype
    )

    flags = (
        win32evtlog.EVENTLOG_BACKWARDS_READ |
        win32evtlog.EVENTLOG_SEQUENTIAL_READ
    )

    events = []

    records = win32evtlog.ReadEventLog(
        handle,
        flags,
        0
    )

    for record in records:

        event = {

            "EventID": record.EventID & 0xFFFF,

            "TimeGenerated":
                record.TimeGenerated,

            "Computer":
                record.ComputerName,

            "User": "Unknown",

            "FailedAttempts": 0,

            "NewDevice": 0

        }

        events.append(event)

    return events


logger.info("=" * 70)
logger.info("Windows Event Monitor Initialized")
logger.info(f"Alert File : {ALERT_FILE}")
logger.info("=" * 70)
# ==============================================================================
# LOAD LABEL ENCODERS
# ==============================================================================

import joblib

ENCODER_DIR = os.path.join(BASE_DIR, "encoders")

ENCODER_FILE = os.path.join(
    ENCODER_DIR,
    "all_encoders.pkl"
)

try:

    ENCODERS = joblib.load(ENCODER_FILE)

    logger.info("Label Encoders Loaded Successfully")

except Exception as e:

    logger.error(f"Unable to load encoders : {e}")

    ENCODERS = {}


# ==============================================================================
# SAFE LABEL ENCODER
# ==============================================================================

def encode_value(column, value):
    """
    Encode categorical values using the saved LabelEncoder.

    Unknown values are mapped to -1.
    """

    try:

        encoder = ENCODERS[column]

        if value in encoder.classes_:

            return int(encoder.transform([value])[0])

        logger.warning(
            f"Unknown value '{value}' for column '{column}'"
        )

        return -1

    except Exception:

        return -1


# ==============================================================================
# UPDATE FEATURE EXTRACTION
# ==============================================================================

def extract_features(event):

    event_time = event.get(
        "TimeGenerated",
        datetime.now()
    )

    hour = event_time.hour

    day = event_time.weekday()

    event_id = event.get("EventID", 0)

    username = str(
        event.get(
            "User",
            "Unknown"
        )
    )

    computer = str(
        event.get(
            "Computer",
            "Unknown"
        )
    )

    auth_type = EVENT_NAMES.get(
        event_id,
        "Unknown"
    )

    logon = str(
        event.get(
            "LogonType",
            "Unknown"
        )
    )

    activity = EVENT_NAMES.get(
        event_id,
        "Unknown"
    )

    result = (
        "Fail"
        if event_id == 4625
        else "Success"
    )

    features = {

        "Hour": hour,

        "DayOfWeek": day,

        "Weekend": weekend_flag(day),

        "IsAdmin": admin_flag(event_id),

        "FailedLogin": failed_login(event_id),

        "FailedAttempts":
            event.get(
                "FailedAttempts",
                0
            ),

        "NewDevice":
            event.get(
                "NewDevice",
                0
            ),

        "SourceUser_enc":
            encode_value(
                "SourceUser",
                username
            ),

        "DestinationUser_enc":
            encode_value(
                "DestinationUser",
                username
            ),

        "SourceComputer_enc":
            encode_value(
                "SourceComputer",
                computer
            ),

        "DestinationComputer_enc":
            encode_value(
                "DestinationComputer",
                computer
            ),

        "AuthenticationType_enc":
            encode_value(
                "AuthenticationType",
                auth_type
            ),

        "LogonType_enc":
            encode_value(
                "LogonType",
                logon
            ),

        "Activity_enc":
            encode_value(
                "Activity",
                activity
            ),

        "Result_enc":
            encode_value(
                "Result",
                result
            )

    }

    return features


# ==============================================================================
# PREDICTION ENGINE
# ==============================================================================

def process_event(event):
    """
    Extract features, perform prediction, and return the result.
    """

    try:

        features = extract_features(event)

        prediction = predict_authentication(features)

        alert = {

            "Timestamp":
                datetime.now(),

            "EventID":
                event.get("EventID"),

            "Computer":
                event.get("Computer"),

            "User":
                event.get("User"),

            "Prediction":
                prediction["prediction"],

            "Risk":
                prediction["risk_level"],

            "Confidence":
                prediction["confidence"],

            "MaliciousProbability":
                prediction["malicious_probability"]

        }

        logger.info(
            f"[{alert['Risk']}] "
            f"{alert['User']} "
            f"({alert['Confidence']:.2f}%)"
        )

        return alert

    except Exception as e:

        logger.error(e)

        return None


# ==============================================================================
# SAVE ALERTS
# ==============================================================================

def save_alert(alert):

    if alert is None:
        return

    df = pd.DataFrame([alert])

    if os.path.exists(ALERT_FILE):

        df.to_csv(
            ALERT_FILE,
            mode="a",
            header=False,
            index=False
        )

    else:

        df.to_csv(
            ALERT_FILE,
            index=False
        )


# ==============================================================================
# PROCESS ALL EVENTS
# ==============================================================================

def process_events(events):

    alerts = []

    for event in events:

        alert = process_event(event)

        if alert is not None:

            save_alert(alert)

            alerts.append(alert)

    return alerts
# ==============================================================================
# ALERT SUMMARY
# ==============================================================================

def alert_statistics(alerts):
    """
    Display summary statistics for processed alerts.
    """

    if not alerts:
        logger.info("No alerts generated.")
        return

    df = pd.DataFrame(alerts)

    logger.info("=" * 70)
    logger.info("Alert Summary")
    logger.info("=" * 70)

    logger.info(f"Total Events Processed : {len(df)}")

    if "Risk" in df.columns:
        logger.info(df["Risk"].value_counts())

    logger.info("=" * 70)


# ==============================================================================
# WINDOWS EVENT MONITOR
# ==============================================================================

class WindowsEventMonitor:

    def __init__(self, poll_interval=5):
        """
        poll_interval : seconds between polling Windows Security Log
        """
        self.poll_interval = poll_interval
        self.running = False

    def monitor_once(self):
        """
        Read and process one batch of Windows events.
        """

        logger.info("Reading Windows Security Events...")

        events = read_windows_events()

        if len(events) == 0:
            logger.info("No new events.")
            return

        alerts = process_events(events)

        alert_statistics(alerts)

    def start(self):

        self.running = True

        logger.info("=" * 70)
        logger.info("Windows Event Monitoring Started")
        logger.info("=" * 70)

        while self.running:

            try:

                self.monitor_once()

                time.sleep(self.poll_interval)

            except KeyboardInterrupt:

                logger.info("Stopping monitor...")

                self.running = False

            except Exception as e:

                logger.exception(e)

                time.sleep(self.poll_interval)

    def stop(self):

        self.running = False

        logger.info("Monitor stopped.")


# ==============================================================================
# SIMULATION MODE
# ==============================================================================

def simulate_events():
    """
    Generates sample events for testing when Windows Event Logs
    are unavailable.
    """

    logger.info("Simulation Mode Enabled")

    sample_events = [

        {
            "EventID": 4624,
            "TimeGenerated": datetime.now(),
            "Computer": "WS001",
            "User": "UserA",
            "FailedAttempts": 0,
            "NewDevice": 0,
            "LogonType": "Network"
        },

        {
            "EventID": 4625,
            "TimeGenerated": datetime.now(),
            "Computer": "WS002",
            "User": "Administrator",
            "FailedAttempts": 4,
            "NewDevice": 1,
            "LogonType": "RemoteInteractive"
        },

        {
            "EventID": 4672,
            "TimeGenerated": datetime.now(),
            "Computer": "SERVER01",
            "User": "Administrator",
            "FailedAttempts": 0,
            "NewDevice": 0,
            "LogonType": "Service"
        }

    ]

    alerts = process_events(sample_events)

    alert_statistics(alerts)


# ==============================================================================
# MAIN
# ==============================================================================

def main():

    logger.info("=" * 70)
    logger.info("AI-Powered Security Operations Platform")
    logger.info("Windows Authentication Event Monitor")
    logger.info("=" * 70)

    if WINDOWS_AVAILABLE:

        monitor = WindowsEventMonitor(
            poll_interval=5
        )

        monitor.start()

    else:

        simulate_events()

    logger.info("Application Finished")


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":

    main()