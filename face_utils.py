import os
import cv2
import json
import numpy as np


# ============================================================
# PATHS
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

FACES_DIR = os.path.join(
    BASE_DIR,
    "data",
    "faces"
)

MODEL_PATH = os.path.join(
    FACES_DIR,
    "face_model.yml"
)

LABELS_PATH = os.path.join(
    FACES_DIR,
    "labels.json"
)

os.makedirs(
    FACES_DIR,
    exist_ok=True
)


# ============================================================
# LOAD FACE DETECTOR
# ============================================================

CASCADE_PATH = os.path.join(
    BASE_DIR,
    "data",
    "haarcascades",
    "haarcascade_frontalface_default.xml"
)

face_detector = cv2.CascadeClassifier(
    CASCADE_PATH
)


# ============================================================
# CHECK CASCADE
# ============================================================

if face_detector.empty():

    raise RuntimeError(
        "OpenCV Haar Cascade could not be loaded.\n"
        f"Expected file:\n{CASCADE_PATH}\n\n"
        "Please reinstall opencv-contrib-python."
    )


# ============================================================
# DETECT FACE
# ============================================================

def detect_face(image_bytes):

    image_array = np.frombuffer(
        image_bytes,
        dtype=np.uint8
    )

    image = cv2.imdecode(
        image_array,
        cv2.IMREAD_COLOR
    )

    if image is None:
        return None

    gray = cv2.cvtColor(
        image,
        cv2.COLOR_BGR2GRAY
    )

    faces = face_detector.detectMultiScale(
        gray,
        scaleFactor=1.1,
        minNeighbors=5,
        minSize=(80, 80)
    )

    if len(faces) == 0:
        return None

    # Select largest face
    x, y, w, h = max(
        faces,
        key=lambda box: box[2] * box[3]
    )

    face = gray[
        y:y + h,
        x:x + w
    ]

    face = cv2.resize(
        face,
        (200, 200)
    )

    return face


# ============================================================
# ENROLL USER
# ============================================================

def enroll_user(
    username,
    image_bytes
):

    face = detect_face(
        image_bytes
    )

    if face is None:

        return (
            False,
            "No face detected. Please position your face clearly in the camera."
        )

    user_dir = os.path.join(
        FACES_DIR,
        username
    )

    os.makedirs(
        user_dir,
        exist_ok=True
    )

    face_path = os.path.join(
        user_dir,
        "0.jpg"
    )

    cv2.imwrite(
        face_path,
        face
    )

    success = train_model()

    if not success:

        return (
            False,
            "Face model training failed."
        )

    return (
        True,
        "Face enrolled successfully."
    )


# ============================================================
# TRAIN MODEL
# ============================================================

def train_model():

    if not hasattr(
        cv2,
        "face"
    ):

        raise RuntimeError(
            "cv2.face is unavailable. "
            "Install opencv-contrib-python."
        )

    recognizer = cv2.face.LBPHFaceRecognizer_create()

    faces = []
    labels = []

    label_map = {}

    label_id = 0

    if not os.path.exists(
        FACES_DIR
    ):
        return False

    for username in sorted(
        os.listdir(FACES_DIR)
    ):

        user_dir = os.path.join(
            FACES_DIR,
            username
        )

        if not os.path.isdir(
            user_dir
        ):
            continue

        user_faces = []

        for filename in os.listdir(
            user_dir
        ):

            if not filename.lower().endswith(
                (".jpg", ".jpeg", ".png")
            ):
                continue

            path = os.path.join(
                user_dir,
                filename
            )

            image = cv2.imread(
                path,
                cv2.IMREAD_GRAYSCALE
            )

            if image is None:
                continue

            image = cv2.resize(
                image,
                (200, 200)
            )

            user_faces.append(
                image
            )

        if not user_faces:
            continue

        label_map[str(label_id)] = username

        for face in user_faces:

            faces.append(
                face
            )

            labels.append(
                label_id
            )

        label_id += 1

    if not faces:

        return False

    recognizer.train(
        faces,
        np.array(labels)
    )

    recognizer.save(
        MODEL_PATH
    )

    with open(
        LABELS_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            label_map,
            file,
            indent=4
        )

    return True


# ============================================================
# VERIFY USER
# ============================================================

def verify_user(
    username,
    image_bytes
):

    face = detect_face(
        image_bytes
    )

    if face is None:

        return (
            False,
            999.0
        )

    if not os.path.exists(
        MODEL_PATH
    ):

        return (
            False,
            999.0
        )

    if not os.path.exists(
        LABELS_PATH
    ):

        return (
            False,
            999.0
        )

    recognizer = cv2.face.LBPHFaceRecognizer_create()

    recognizer.read(
        MODEL_PATH
    )

    with open(
        LABELS_PATH,
        "r",
        encoding="utf-8"
    ) as file:

        label_map = json.load(
            file
        )

    label, confidence = recognizer.predict(
        face
    )

    predicted_username = label_map.get(
        str(label)
    )

    # Lower confidence = better match
    matched = (
        predicted_username == username
        and confidence < 70
    )

    return (
        matched,
        float(confidence)
    )