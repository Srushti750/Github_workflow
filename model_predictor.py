import os
from pathlib import Path
import pickle
import numpy as np
from keras.models import load_model
from keras_preprocessing.sequence import pad_sequences
import gdown  # For Google Drive downloads

# Constants
MAX_SEQ_LENGTH = 50  # Match your training setting

# Google Drive file IDs (replace with your actual file IDs)
DRIVE_FILE_IDS = {
    "sql_dataset_finaltest_X": "YOUR_DRIVE_FILE_ID_1",
    "sql_dataset_finaltest_Y": "16b0YKbDh4hDTC7oOfWBNgMk5BIa-tZoE",
    "command_injection_dataset_finaltest_X": "YOUR_DRIVE_FILE_ID_3",
    "command_injection_dataset_finaltest_Y": "1cCAgb7zDwOiT12CHYA3AaDBwFZH7tlEz",
    "LSTM_model_sql.h5": "1OVHXTrVCFYclFt676ApwfbbGHFJ14jWy",
    "LSTM_model_command_injection.h5": "1RZ0bbtkr_EXf-1EaXWXFJVIls5gIlwCZ"
}

def get_project_root():
    """Returns absolute path to project root"""
    return Path(__file__).resolve().parent.parent

def ensure_directory_exists(path):
    """Create directory if it doesn't exist"""
    os.makedirs(path, exist_ok=True)
    return path

def download_from_drive(filename, destination):
    """Download file from Google Drive if it doesn't exist"""
    if not os.path.exists(destination):
        print(f"Downloading {filename} from Google Drive...")
        url = f"https://drive.google.com/uc?id={DRIVE_FILE_IDS[filename]}"
        gdown.download(url, destination, quiet=False)
    return destination

def get_data_path(filename):
    """Get verified path to data files, downloading if necessary"""
    if "dataset" in filename:
        dir_path = ensure_directory_exists(get_project_root() / "data")
        file_path = dir_path / filename
    else:  # Model file
        dir_path = ensure_directory_exists(get_project_root() / "model")
        file_path = dir_path / filename
    
    return download_from_drive(filename, str(file_path))

def load_dataset(mode):
    """Load preprocessed dataset with path verification"""
    x_path = get_data_path(f"{mode}_dataset_finaltest_X")
    y_path = get_data_path(f"{mode}_dataset_finaltest_Y")
    
    with open(x_path, "rb") as f:
        X = pickle.load(f)
    with open(y_path, "rb") as f:
        y = pickle.load(f)
    
    return X, y

def preprocess_code(code, mode):
    """Convert raw code to model input format"""
    X, _ = load_dataset(mode)
    sample_shape = np.array(X[0]).shape if len(X) > 0 else (MAX_SEQ_LENGTH,)
    
    return pad_sequences(
        [np.zeros(sample_shape)],
        maxlen=MAX_SEQ_LENGTH,
        padding='post',
        truncating='post',
        dtype='float32'
    )

def lstm_predict(code, mode):
    """LSTM model prediction"""
    model_path = get_data_path(f"LSTM_model_{mode}.h5")
    model = load_model(
        model_path,
        custom_objects={'f1_loss': None, 'f1': None},  # Replace with your actual objects
        compile=False
    )
    
    processed = preprocess_code(code, mode)
    confidence = model.predict(processed, verbose=0)[0][0]
    return confidence

def pattern_match_command_injection(code):
    """Heuristic pattern matching for command injection"""
    dangerous_patterns = [
        "os.system(",
        "subprocess.run(",
        "subprocess.call(",
        "subprocess.Popen(",
        "os.popen(",
        "eval(",
        "exec(",
        "shell=True"
    ]
    
    for pattern in dangerous_patterns:
        if pattern in code:
            return True
    return False

def predict_vulnerability(code, mode="sql"):
    """
    Combined vulnerability prediction using:
    1. Pattern matching (for command injection)
    2. LSTM model (for both SQLi and command injection)
    """
    confidence = 0.0
    
    # Special case: Command injection pattern matching
    if mode == "command_injection" and pattern_match_command_injection(code):
        confidence = 0.9  # High confidence for pattern matches
    
    # Fall back to LSTM model if no pattern match or for SQLi
    if confidence < 0.5:
        confidence = lstm_predict(code, mode)
    
    return {
        "type": mode,
        "confidence": float(confidence),
        "is_vulnerable": confidence >= 0.3,
        "detection_method": "pattern" if confidence >= 0.9 else "model"
    }