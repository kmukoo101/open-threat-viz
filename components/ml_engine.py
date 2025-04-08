import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder
from typing import List, Dict

def preprocess_iocs(iocs: Dict[str, List[Dict[str, str]]]) -> pd.DataFrame:
    """
    Convert IOC dictionary into a feature-rich DataFrame for ML analysis.
    Categorical fields are encoded.
    """
    rows = []
    for feed, entries in iocs.items():
        for entry in entries:
            rows.append({
                "feed": feed,
                "type": entry.get("type", "unknown"),
                "value": entry.get("value", ""),
                "source": entry.get("source", feed),
                "confidence": float(entry.get("confidence", 0.5))
            })
    
    df = pd.DataFrame(rows)

    # Encode categorical columns for ML
    for col in ["feed", "type", "source"]:
        if col in df.columns:
            df[col] = LabelEncoder().fit_transform(df[col].astype(str))

    return df

def detect_anomalies(df: pd.DataFrame, contamination: float = 0.05) -> pd.DataFrame:
    """
    Detect anomalies in IOC data using Isolation Forest.
    Returns the DataFrame with a new 'anomaly' column (1 = outlier).
    """
    if df.empty or len(df) < 5:
        df["anomaly"] = 0
        return df

    features = ["feed", "type", "source", "confidence"]
    X = df[features]

    model = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    df["anomaly"] = model.fit_predict(X)
    
    return df

def get_anomalies_only(df: pd.DataFrame) -> pd.DataFrame:
    """Return only IOC rows marked as anomalies."""
    return df[df["anomaly"] == -1]
