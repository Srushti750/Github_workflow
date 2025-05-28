import os
from pathlib import Path
import pickle
import numpy as np
from keras.models import load_model
from keras_preprocessing.sequence import pad_sequences
import gdown
import glob

# Constants
MAX_SEQ_LENGTH = 50

# Google Drive file IDs
DRIVE_FILE_IDS = {
    "sql_dataset_finaltest_Y": "16b0YKbDh4hDTC7oOfWBNgMk5BIa-tZoE",
    "command_injection_dataset_finaltest_Y": "1cCAgb7zDwOiT12CHYA3AaDBwFZH7tlEz",
    "LSTM_model_sql.h5": "1OVHXTrVCFYclFt676ApwfbbGHFJ14jWy",
    "LSTM_model_command_injection.h5": "1RZ0bbtkr_EXf-1EaXWXFJVIls5gIlwCZ",
}

# Define chunks
COMMAND_CHUNKS = [f"data/part_{ch}" for ch in ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai", "aj", "ak", "al", "am", "an", "ao", "ap"]]
SQL_CHUNKS = [f"data/part_{ch}" for ch in ["aa", "ab", "ac", "ad", "ae", "af", "ag", "ah", "ai","aj", "ak","al","am","an","ao","ap","aq","as","at","au","av","aw","ax","ay","az","ba","bb","bc","bd","be","bf","bg","bh"]]

def reassemble_file(chunk_list, output_path):
    """Combine chunks into one file"""
    with open(output_path, "wb") as outfile:
        for part in chunk_list:
            with open(part, "rb") as infile:
                outfile.write(infile.read())
    # Cleanup
    for part in chunk_list:
        os.remove(part)

def download_file_from_drive(file_id, output_path):
    # TODO: Change the drive url
    gdown.download(f"https://drive.google.com/uc?id={file_id}", str(output_path), quiet=False)

def ensure_data_available(filename):
    data_dir = Path("data")
    model_dir = Path("model")
    data_dir.mkdir(parents=True, exist_ok=True)
    model_dir.mkdir(parents=True, exist_ok=True)

    file_path = data_dir / filename if filename.startswith("sql") or filename.startswith("command") else model_dir / filename
    if file_path.exists():
        return

    print(f"Preparing {filename}...")
    if filename == "command_injection_dataset_finaltest_X":
        print("Downloading command injection chunks...")
        for idx, part in enumerate(COMMAND_CHUNKS[:2]):
            # TODO: Change the drive url
            gdown.download(f"https://drive.google.com/uc?id=CHUNK_ID_{idx+1}", part, quiet=False)
        reassemble_file(COMMAND_CHUNKS[:2], data_dir / filename)

    elif filename == "sql_dataset_finaltest_X":
        print("Downloading SQL injection chunks...")
        for idx, part in enumerate(SQL_CHUNKS):
            # TODO: Change the drive url
            gdown.download(f"https://drive.google.com/uc?id=SQL_CHUNK_ID_{idx+1}", part, quiet=False)
        reassemble_file(SQL_CHUNKS, data_dir / filename)

    elif filename in DRIVE_FILE_IDS:
        print(f"Downloading {filename} from Drive...")
        download_file_from_drive(DRIVE_FILE_IDS[filename], file_path)

    else:
        raise ValueError(f"No handling logic for {filename}")

def get_data_path(filename):
    ensure_data_available(filename)
    path = Path("data") / filename
    if not path.exists():
        raise FileNotFoundError(f"{filename} not found even after download")
    return str(path)

def get_model_path(filename):
    ensure_data_available(filename)
    path = Path("model") / filename
    if not path.exists():
        raise FileNotFoundError(f"{filename} not found even after download")
    return str(path)

def load_dataset(mode):
    x_path = get_data_path(f"{mode}_dataset_finaltest_X")
    y_path = get_data_path(f"{mode}_dataset_finaltest_Y")
    with open(x_path, "rb") as f:
        X = pickle.load(f)
    with open(y_path, "rb") as f:
        y = pickle.load(f)
    return X, y

def preprocess_code(code, mode):
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
    model_path = get_model_path(f"LSTM_model_{mode}.h5")
    model = load_model(model_path, custom_objects={'f1_loss': None, 'f1': None}, compile=False)
    processed = preprocess_code(code, mode)
    confidence = model.predict(processed, verbose=0)[0][0]
    return confidence

def pattern_match_command_injection(code):
    dangerous_patterns = [
        "os.system(", "subprocess.run(", "subprocess.call(", "subprocess.Popen(",
        "os.popen(", "eval(", "exec(", "shell=True"
    ]
    return any(p in code for p in dangerous_patterns)

def predict_vulnerability(code, mode):
    confidence = lstm_predict(code, mode)
    return {
        "type": mode,
        "confidence": float(confidence),
        "is_vulnearble": confidence >= 0.3,
    }

# def predict_vulnerability(code, mode="sql"):
#     confidence = 0.0
#     if mode == "command_injection" and pattern_match_command_injection(code):
#         confidence = 0.9
#     if confidence < 0.5:
#         confidence = lstm_predict(code, mode)
#     return {
#         "type": mode,
#         "confidence": float(confidence),
#         "is_vulnerable": confidence >= 0.3,
#         "detection_method": "pattern" if confidence >= 0.9 else "model"
#     }
