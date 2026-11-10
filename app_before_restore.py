
import streamlit as st
import pandas as pd
import numpy as np
import joblib

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix
)

# ==================================================
# PAGE CONFIGURATION
# ==================================================

st.set_page_config(
    page_title="Hybrid Zero-Day Attack Detection",
    page_icon="🛡️",
    layout="wide"
)

# ==================================================
# CYBERGUARD UI STYLING
# ==================================================

st.markdown("""
<style>

.stApp {
    background-color: #0B1120;
    color: #E5E7EB;
}

[data-testid="stSidebar"] {
    background-color: #242631;
    border-right: 1px solid #343746;
}

[data-testid="stSidebar"] h1,
[data-testid="stSidebar"] h2,
[data-testid="stSidebar"] h3 {
    color: #FFFFFF;
}

h1, h2, h3 {
    color: #F8FAFC;
}

.stMetric {
    background-color: #151C2C;
    padding: 18px;
    border-radius: 12px;
    border: 1px solid #263247;
}

.stButton > button {
    background-color: #2563EB;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 10px 20px;
}

.stButton > button:hover {
    background-color: #1D4ED8;
    color: white;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #263247;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)


# ==================================================
# CYBERGUARD SIDEBAR
# ==================================================

with st.sidebar:

    st.markdown(
        "<h1 style='text-align:center;'>🛡️ CYBERGUARD</h1>",
        unsafe_allow_html=True
    )

    st.markdown(
        "<p style='text-align:center;color:#94A3B8;'>"
        "Zero-Day Detection Platform</p>",
        unsafe_allow_html=True
    )

    st.divider()

    st.subheader("🧭 Navigation")

    selected_page = st.radio(
        "Navigate",
        [
            "🏠 Dashboard",
            "🔍 Traffic Detection",
            "🧩 Attack Classification",
            "📊 Model Evaluation",
            "📄 Detection Reports"
        ],
        label_visibility="collapsed"
    )

    st.divider()

    st.subheader("⚙️ System Information")

    st.success("Detection Model: Loaded")
    st.success("Category Model: Loaded")

    st.caption("Dataset: UNSW-NB15")
    st.caption("Framework: Streamlit")
    st.caption("Models: Random Forest + Anomaly Detection")

# ==================================================
# CUSTOM CYBERSECURITY DASHBOARD THEME
# ==================================================

st.markdown("""
<style>

/* Main application background */
.stApp {
    background-color: #0b1120;
    color: #e2e8f0;
}

/* Main content spacing */
.block-container {
    padding-top: 2rem;
    padding-bottom: 2rem;
    max-width: 1500px;
}

/* Main headings */
h1 {
    color: #f8fafc !important;
    font-weight: 800 !important;
    letter-spacing: -1px;
}

h2, h3 {
    color: #e2e8f0 !important;
    font-weight: 700 !important;
}

/* Metric cards */
[data-testid="stMetric"] {
    background: linear-gradient(135deg, #111c32, #16243b);
    border: 1px solid #263752;
    padding: 20px;
    border-radius: 14px;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.2);
}

[data-testid="stMetricLabel"] {
    color: #94a3b8 !important;
    font-size: 14px;
}

[data-testid="stMetricValue"] {
    color: #38bdf8 !important;
    font-size: 30px !important;
    font-weight: 800 !important;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(90deg, #2563eb, #0ea5e9);
    color: white;
    border: none;
    border-radius: 10px;
    padding: 10px 22px;
    font-weight: 700;
    transition: 0.2s ease;
}

.stButton > button:hover {
    background: linear-gradient(90deg, #1d4ed8, #0284c7);
    border: none;
    transform: translateY(-2px);
}

/* Download buttons */
.stDownloadButton > button {
    background-color: #0f766e;
    color: white;
    border-radius: 10px;
    border: none;
    font-weight: 700;
}

/* Data tables */
[data-testid="stDataFrame"] {
    border: 1px solid #263752;
    border-radius: 10px;
    overflow: hidden;
}

/* Expanders */
[data-testid="stExpander"] {
    background-color: #111c32;
    border: 1px solid #263752;
    border-radius: 10px;
}

/* File uploader */
[data-testid="stFileUploader"] {
    background-color: #111c32;
    border: 1px dashed #334e68;
    border-radius: 12px;
    padding: 15px;
}

/* Info messages */
[data-testid="stAlert"] {
    border-radius: 10px;
}

/* Horizontal separators */
hr {
    border-color: #263752;
}

/* Hide Streamlit branding */
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

</style>
""", unsafe_allow_html=True)

# ==================================================
# ATTACK CATEGORY INFORMATION
# ==================================================

attack_information = {
    "Analysis": {
        "description": "Traffic associated with analysis or probing activity.",
        "impact": "May indicate attempts to study network behavior or identify weaknesses.",
        "response": "Review network logs, investigate source addresses, and monitor unusual traffic."
    },

    "Backdoor": {
        "description": "Activity potentially associated with unauthorized hidden access.",
        "impact": "Could allow unauthorized access or persistent control of a system.",
        "response": "Isolate the affected system, inspect processes, and investigate persistence."
    },

    "DoS": {
        "description": "Denial-of-Service activity.",
        "impact": "May degrade or disrupt the availability of network services.",
        "response": "Review traffic volume, apply filtering or rate limiting, and monitor service availability."
    },

    "Exploits": {
        "description": "Traffic potentially associated with exploitation of vulnerabilities.",
        "impact": "Could compromise vulnerable applications or systems.",
        "response": "Check affected services, apply security patches, and investigate suspicious activity."
    },

    "Fuzzers": {
        "description": "Activity involving unusual or malformed inputs sent to services.",
        "impact": "May expose software weaknesses or cause unexpected application behavior.",
        "response": "Inspect affected services, review application logs, and validate input handling."
    },

    "Generic": {
        "description": "Attack traffic categorized as Generic by the dataset.",
        "impact": "May indicate malicious traffic without a more specific assigned category.",
        "response": "Investigate traffic patterns, source addresses, and related security alerts."
    },

    "Reconnaissance": {
        "description": "Network or system information-gathering activity.",
        "impact": "May precede an attempt to exploit or compromise a system.",
        "response": "Review scan activity, restrict unnecessary exposed services, and monitor the source."
    },

    "Shellcode": {
        "description": "Traffic associated with shellcode-related activity.",
        "impact": "Could indicate attempts to execute unauthorized code.",
        "response": "Investigate the affected host, inspect processes, and review endpoint security logs."
    },

    "Worms": {
        "description": "Traffic associated with worm-like activity.",
        "impact": "Could indicate attempts at automated propagation between systems.",
        "response": "Investigate affected hosts, isolate suspected systems, and check for lateral movement."
    },

    "Unknown / Unclassified": {
        "description": "The detection model flagged this traffic as suspicious, but the attack-category model could not assign a reliable known category.",
        "impact": "The activity may represent an unfamiliar attack, an unusual traffic pattern, or a category classification error.",
        "response": "Investigate the traffic manually, review network and endpoint logs, and apply appropriate security monitoring."
    },

    "Normal": {
        "description": "Traffic classified as Normal by the detection model.",
        "impact": "No suspicious activity was identified by the binary detection model.",
        "response": "Continue routine monitoring."
    }
}

# ==================================================
# LOAD SAVED MODELS
# ==================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

zero_day_bundle = joblib.load(
    os.path.join(BASE_DIR, "zero_day_detection_model.pkl")
)

category_bundle = joblib.load(
    os.path.join(BASE_DIR, "attack_category_model.pkl")
)

zero_day_model = zero_day_bundle["model"]
zero_day_preprocessor = zero_day_bundle["preprocessor"]
threshold = zero_day_bundle["threshold"]

category_model = category_bundle["model"]
category_preprocessor = category_bundle["preprocessor"]

# ==================================================
# PAGE HEADER
# ==================================================

st.title("🛡️ Hybrid Zero-Day Attack Detection System")

st.write(
    "Machine Learning-Based Network Traffic Analysis, "
    "Suspicious Activity Detection, and Attack Classification"
)

st.info(
    "Upload a network traffic CSV containing the raw "
    "features required by the trained models."
)

if selected_page == "🔍 Traffic Detection":
    # ==================================================
    # FILE UPLOAD
    # ==================================================

    uploaded_file = st.file_uploader(
        "Upload Network Traffic CSV",
        type=["csv"]
    )

    if uploaded_file is not None:

        data = pd.read_csv(uploaded_file)

        st.subheader("Uploaded Dataset")

        col1, col2 = st.columns(2)

        col1.metric("Total Records", len(data))
        col2.metric("Total Columns", data.shape[1])

        st.dataframe(
            data.head(10),
            use_container_width=True
        )

        if st.button("🔍 Detect Attacks", type="primary"):

            zero_day_features = list(
                zero_day_preprocessor.feature_names_in_
            )

            category_features = list(
                category_preprocessor.feature_names_in_
            )

            required_features = list(
                dict.fromkeys(
                    zero_day_features + category_features
                )
            )

            missing_features = [
                feature for feature in required_features
                if feature not in data.columns
            ]

            if missing_features:

                st.error(
                    "Missing required features: "
                    + ", ".join(missing_features)
                )

            else:

                with st.spinner("Analyzing network traffic..."):

                    # ------------------------------------------
                    # PREPROCESS DATA FOR BOTH MODELS
                    # ------------------------------------------

                    zero_input = data[
                        zero_day_features
                    ].copy()

                    category_input = data[
                        category_features
                    ].copy()

                    zero_processed = (
                        zero_day_preprocessor.transform(
                            zero_input
                        )
                    )

                    category_processed = (
                        category_preprocessor.transform(
                            category_input
                        )
                    )

                    # ------------------------------------------
                    # ZERO-DAY / SUSPICIOUS TRAFFIC DETECTION
                    # ------------------------------------------

                    attack_probabilities = (
                        zero_day_model.predict_proba(
                            zero_processed
                        )[:, 1]
                    )

                    zero_day_predictions = (
                        attack_probabilities >= threshold
                    ).astype(int)

                    # ------------------------------------------
                    # ATTACK CATEGORY PREDICTION
                    # ------------------------------------------

                    category_predictions = (
                        category_model.predict(
                            category_processed
                        )
                    )

                    # ------------------------------------------
                    # CREATE DETECTION REPORT
                    # ------------------------------------------

                    report = data.copy()

                    report["Attack_Probability"] = (
                        attack_probabilities
                    )

                    report["Zero_Day_Prediction"] = (
                        zero_day_predictions
                    )

                    report["Detection_Result"] = [
                        "Attack / Suspicious"
                        if prediction == 1
                        else "Normal"
                        for prediction in zero_day_predictions
                    ]

                    # FIX:
                    # Suspicious traffic should not be labeled Normal
                    # just because the category model predicts Normal.

                    predicted_categories = []

                    for i in range(len(data)):

                        if zero_day_predictions[i] == 0:

                            predicted_categories.append(
                                "Normal"
                            )

                        else:

                            category = str(
                                category_predictions[i]
                            )

                            if category.strip().lower() == "normal":

                                predicted_categories.append(
                                    "Unknown / Unclassified"
                                )

                            else:

                                predicted_categories.append(
                                    category
                                )

                    report[
                        "Predicted_Attack_Category"
                    ] = predicted_categories

                                        # ------------------------------------------
                    # SAVE REPORT FOR DETECTION REPORTS PAGE
                    # ------------------------------------------

                    st.session_state["latest_detection_report"] = (
                        report.copy()
                    )

                    st.session_state["latest_detection_summary"] = {
                        "total_records": len(report),
                        "normal_count": int(
                            (zero_day_predictions == 0).sum()
                        ),
                        "suspicious_count": int(
                            (zero_day_predictions == 1).sum()
                        )
                    }

                    # ==========================================
                    # DETECTION SUMMARY
                    # ==========================================

                    st.divider()

                    st.header(
                        "📊 Detection Summary"
                    )

                    total_records = len(report)

                    normal_count = int(
                        (zero_day_predictions == 0).sum()
                    )

                    suspicious_count = int(
                        (zero_day_predictions == 1).sum()
                    )

                    col1, col2, col3 = st.columns(3)

                    col1.metric(
                        "Total Records",
                        total_records
                    )

                    col2.metric(
                        "Normal Traffic",
                        normal_count
                    )

                    col3.metric(
                        "Suspicious Traffic",
                        suspicious_count
                    )

                    # ==========================================
                    # ATTACK CATEGORY SUMMARY
                    # ==========================================

                    st.subheader(
                        "🧩 Predicted Attack Categories"
                    )

                    suspicious_records = report[
                        report["Zero_Day_Prediction"] == 1
                    ]

                    if len(suspicious_records) > 0:

                        category_counts = (
                            suspicious_records[
                                "Predicted_Attack_Category"
                            ]
                            .value_counts()
                            .rename_axis("Attack Category")
                            .reset_index(name="Count")
                        )

                        st.dataframe(
                            category_counts,
                            use_container_width=True
                        )

                        st.bar_chart(
                            category_counts.set_index(
                                "Attack Category"
                            )
                        )

                    else:

                        st.success(
                            "No suspicious records were detected "
                            "in this dataset."
                        )

                    # ==========================================
                    # DETECTION RESULTS
                    # ==========================================

                    st.subheader(
                        "🔍 Detection Results"
                    )

                    display_columns = [
                        "Attack_Probability",
                        "Detection_Result",
                        "Predicted_Attack_Category"
                    ]

                    st.dataframe(
                        report[display_columns],
                        use_container_width=True
                    )

                    # ==========================================
                    # ATTACK CATEGORY ANALYSIS
                    # ==========================================

                    st.divider()

                    st.header(
                        "🛡️ Attack Category Analysis"
                    )

                    st.write(
                        "Understand the predicted attack categories, "
                        "their potential impact, and recommended "
                        "defensive actions."
                    )

                    category_counts = (
                        suspicious_records[
                            "Predicted_Attack_Category"
                        ].value_counts()
                    )

                    if len(category_counts) > 0:

                        for category, count in category_counts.items():

                            information = attack_information.get(
                                category,
                                {
                                    "description": (
                                        "No specific category "
                                        "information is available."
                                    ),

                                    "impact": (
                                        "The traffic may represent "
                                        "a potentially suspicious "
                                        "or unfamiliar activity."
                                    ),

                                    "response": (
                                        "Investigate the traffic using "
                                        "security monitoring tools."
                                    )
                                }
                            )

                            with st.expander(
                                f"🔎 {category} — "
                                f"{count} suspicious records"
                            ):

                                st.write(
                                    "**Description:**"
                                )

                                st.write(
                                    information["description"]
                                )

                                st.write(
                                    "**Potential Impact:**"
                                )

                                st.write(
                                    information["impact"]
                                )

                                st.write(
                                    "**Recommended Response:**"
                                )

                                st.write(
                                    information["response"]
                                )

                    else:

                        st.info(
                            "No suspicious attack categories "
                            "are available for analysis."
                        )

                    # ==========================================
                    # MODEL EVALUATION
                    # ==========================================

                    st.divider()

                    st.header(
                        "📈 Model Evaluation Dashboard"
                    )

                    if "label" in data.columns:

                        actual_labels = (
                            data["label"].astype(int)
                        )

                        accuracy = accuracy_score(
                            actual_labels,
                            zero_day_predictions
                        )

                        precision = precision_score(
                            actual_labels,
                            zero_day_predictions,
                            zero_division=0
                        )

                        recall = recall_score(
                            actual_labels,
                            zero_day_predictions,
                            zero_division=0
                        )

                        f1 = f1_score(
                            actual_labels,
                            zero_day_predictions,
                            zero_division=0
                        )

                        col1, col2, col3, col4 = (
                            st.columns(4)
                        )

                        col1.metric(
                            "Accuracy",
                            f"{accuracy:.2%}"
                        )

                        col2.metric(
                            "Precision",
                            f"{precision:.2%}"
                        )

                        col3.metric(
                            "Recall",
                            f"{recall:.2%}"
                        )

                        col4.metric(
                            "F1-Score",
                            f"{f1:.2%}"
                        )

                        cm = confusion_matrix(
                            actual_labels,
                            zero_day_predictions,
                            labels=[0, 1]
                        )

                        tn, fp, fn, tp = cm.ravel()

                        st.subheader(
                            "Confusion Matrix"
                        )

                        confusion_df = pd.DataFrame(
                            cm,
                            index=[
                                "Actual Normal",
                                "Actual Attack"
                            ],
                            columns=[
                                "Predicted Normal",
                                "Predicted Attack"
                            ]
                        )

                        st.dataframe(
                            confusion_df,
                            use_container_width=True
                        )

                        col1, col2, col3, col4 = (
                            st.columns(4)
                        )

                        col1.metric(
                            "True Negatives",
                            int(tn)
                        )

                        col2.metric(
                            "False Positives",
                            int(fp)
                        )

                        col3.metric(
                            "False Negatives",
                            int(fn)
                        )

                        col4.metric(
                            "True Positives",
                            int(tp)
                        )

                        st.caption(
                            "These evaluation metrics use the actual "
                            "binary labels in the uploaded dataset."
                        )

                    else:

                        st.warning(
                            "The uploaded dataset has no 'label' column. "
                            "Predictions are shown, but evaluation "
                            "metrics cannot be calculated."
                        )

                    # ==========================================
                    # COMPLETE REPORT
                    # ==========================================

                    st.divider()

                    st.subheader(
                        "📄 Complete Detection Report"
                    )

                    st.dataframe(
                        report,
                        use_container_width=True
                    )

                    csv_report = report.to_csv(
                        index=False
                    ).encode("utf-8")

                    st.download_button(
                        label=(
                            "📥 Download Complete "
                            "Detection Report"
                        ),

                        data=csv_report,

                        file_name=(
                            "hybrid_zero_day_detection_report.csv"
                        ),

                        mime="text/csv"
                    )

                                        # ==========================================
                    # SAVE LATEST DETECTION REPORT
                    # ==========================================

                    st.session_state["latest_detection_report"] = (
                        report.copy()
                    )

                    st.session_state["latest_detection_summary"] = {
                        "total_records": int(total_records),
                        "normal_count": int(normal_count),
                        "suspicious_count": int(suspicious_count)
                    }

                    st.success(
                        "Traffic analysis completed successfully!"
                    )

                    # ==================================================
# ATTACK CLASSIFICATION PAGE
# ==================================================

if selected_page == "🧩 Attack Classification":

    st.header("🧩 Attack Classification")

    st.write(
        "Identify the potential attack category in network traffic "
        "using the trained machine learning classification model."
    )

    st.info(
        "Upload a CSV containing the raw network traffic features "
        "required by the trained category model."
    )

    category_file = st.file_uploader(
        "Upload CSV for Attack Classification",
        type=["csv"],
        key="category_upload"
    )

    if category_file is not None:

        category_data = pd.read_csv(category_file)

        st.subheader("Uploaded Dataset")

        st.metric("Total Records", len(category_data))

        st.dataframe(
            category_data.head(10),
            use_container_width=True
        )

        if st.button(
            "🧩 Classify Attacks",
            type="primary",
            key="classify_attacks"
        ):

            required_features = list(
                category_preprocessor.feature_names_in_
            )

            missing_features = [
                feature for feature in required_features
                if feature not in category_data.columns
            ]

            if missing_features:

                st.error(
                    "Missing required features: "
                    + ", ".join(missing_features)
                )

            else:

                with st.spinner("Classifying network traffic..."):

                    category_input = category_data[
                        required_features
                    ].copy()

                    category_processed = (
                        category_preprocessor.transform(
                            category_input
                        )
                    )

                    category_predictions = (
                        category_model.predict(
                            category_processed
                        )
                    )

                    classification_report = (
                        category_data.copy()
                    )

                    classification_report[
                        "Predicted_Attack_Category"
                    ] = category_predictions

                st.success("Attack classification completed!")

                st.subheader("Classification Summary")

                category_counts = (
                    classification_report[
                        "Predicted_Attack_Category"
                    ]
                    .value_counts()
                    .rename_axis("Category")
                    .reset_index(name="Records")
                )

                st.dataframe(
                    category_counts,
                    use_container_width=True
                )

                st.bar_chart(
                    category_counts.set_index("Category"),
                    height=400
                )

                st.subheader("Classification Results")

                st.dataframe(
                    classification_report[
                        [
                            "Predicted_Attack_Category"
                        ]
                    ],
                    use_container_width=True
                )

                st.subheader("Category Information")

                for category in category_counts["Category"]:

                    information = attack_information.get(
                        category,
                        {
                            "description": "No description available.",
                            "impact": "Potential impact is unknown.",
                            "response": "Investigate the traffic manually."
                        }
                    )

                    with st.expander(str(category)):

                        st.write(
                            "**Description:**",
                            information["description"]
                        )

                        st.write(
                            "**Potential Impact:**",
                            information["impact"]
                        )

                        st.write(
                            "**Recommended Response:**",
                            information["response"]
                        )

                csv_data = classification_report.to_csv(
                    index=False
                ).encode("utf-8")

                st.download_button(
                    "📥 Download Classification Report",
                    data=csv_data,
                    file_name="attack_classification_report.csv",
                    mime="text/csv",
                    key="download_classification"
                )

                # ==================================================
# DETECTION REPORTS PAGE
# ==================================================

if selected_page == "📄 Detection Reports":

    st.header("📄 Detection Reports")

    st.write(
        "View and download the latest network traffic detection report."
    )

    if "latest_detection_report" not in st.session_state:

        st.warning(
            "No detection report is available yet. "
            "Go to Traffic Detection, upload a CSV file, "
            "and run the analysis first."
        )

    else:

        report = st.session_state[
            "latest_detection_report"
        ]

        summary = st.session_state.get(
            "latest_detection_summary",
            {}
        )

        st.subheader("📊 Detection Summary")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Records",
            summary.get("total_records", len(report))
        )

        col2.metric(
            "Normal Records",
            summary.get("normal_count", "N/A")
        )

        col3.metric(
            "Suspicious Records",
            summary.get("suspicious_count", "N/A")
        )

        st.divider()

        st.subheader("📋 Complete Detection Report")

        st.dataframe(
            report,
            use_container_width=True,
            height=500
        )

        st.subheader("📥 Download Report")

        csv_report = report.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="Download Detection Report (CSV)",
            data=csv_report,
            file_name="zero_day_detection_report.csv",
            mime="text/csv",
            key="download_detection_report"
        )
# ==================================================
# DETECTION REPORTS PAGE
# ==================================================

if selected_page == "📄 Detection Reports":

    st.header("📄 Detection Reports")

    st.write(
        "View and download the latest network traffic "
        "detection report generated by the system."
    )

    if "latest_detection_report" not in st.session_state:

        st.warning(
            "No detection report is available yet. "
            "Please navigate to Traffic Detection, upload "
            "a CSV dataset, and run the analysis first."
        )

    else:

        report = st.session_state[
            "latest_detection_report"
        ]

        summary = st.session_state.get(
            "latest_detection_summary",
            {}
        )

        # ==========================================
        # DETECTION SUMMARY
        # ==========================================

        st.subheader("📊 Detection Summary")

        col1, col2, col3 = st.columns(3)

        col1.metric(
            "Total Records",
            summary.get("total_records", len(report))
        )

        col2.metric(
            "Normal Traffic",
            summary.get("normal_count", "N/A")
        )

        col3.metric(
            "Suspicious Traffic",
            summary.get("suspicious_count", "N/A")
        )

        st.divider()

        # ==========================================
        # CATEGORY SUMMARY
        # ==========================================

        st.subheader("🧩 Attack Category Summary")

        if "Predicted_Attack_Category" in report.columns:

            suspicious_records = report[
                report["Zero_Day_Prediction"] == 1
            ]

            if not suspicious_records.empty:

                category_counts = (
                    suspicious_records[
                        "Predicted_Attack_Category"
                    ]
                    .value_counts()
                    .rename_axis("Attack Category")
                    .reset_index(name="Records")
                )

                st.dataframe(
                    category_counts,
                    use_container_width=True,
                    hide_index=True
                )

                st.bar_chart(
                    category_counts.set_index(
                        "Attack Category"
                    ),
                    height=350
                )

            else:

                st.success(
                    "No suspicious traffic was detected "
                    "in the latest report."
                )

        st.divider()

        # ==========================================
        # COMPLETE REPORT
        # ==========================================

        st.subheader("📋 Complete Detection Report")

        st.dataframe(
            report,
            use_container_width=True,
            height=500
        )

        # ==========================================
        # DOWNLOAD REPORT
        # ==========================================

        st.subheader("📥 Download Report")

        csv_report = report.to_csv(
            index=False
        ).encode("utf-8")

        st.download_button(
            label="📥 Download Detection Report (CSV)",
            data=csv_report,
            file_name="hybrid_zero_day_detection_report.csv",
            mime="text/csv",
            key="download_detection_report_csv"
        )

        st.success(
            "The latest detection report is ready."
        )

if selected_page == "🏠 Dashboard":
    # ==================================================
    # MODEL PERFORMANCE COMPARISON DASHBOARD
    # ==================================================

    st.divider()

    st.header(
        "📊 Model Performance Comparison Dashboard"
    )

    st.write(
        "Comparison of the supervised, anomaly detection, "
        "and hybrid approaches evaluated on UNSW-NB15."
    )

        # ==================================================
    # DASHBOARD KPI CARDS
    # ==================================================

    st.markdown("### 📌 System Performance Overview")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric(
        "Hybrid Model Accuracy",
        "85.54%",
        help="Overall accuracy of the hybrid model."
    )

    col2.metric(
        "Hybrid Model Recall",
        "97.72%",
        help="Percentage of actual attacks detected."
    )

    col3.metric(
        "Zero-Day Detection Rate",
        "98.08%",
        help="Detection rate in the simulated zero-day experiment."
    )

    col4.metric(
        "Dataset",
        "UNSW-NB15",
        help="Dataset used for model development and evaluation."
    )

    st.divider()

    comparison_data = pd.DataFrame({

        "Model": [
            "Random Forest",
            "Isolation Forest",
            "Hybrid"
        ],

        "Accuracy": [
            87.80,
            58.54,
            85.54
        ],

        "Precision": [
            83.32,
            82.30,
            80.29
        ],

        "Recall": [
            97.33,
            31.47,
            97.72
        ],

        "F1-Score": [
            89.78,
            45.54,
            88.15
        ],

        "False Positive Rate": [
            23.87,
            8.29,
            29.39
        ],

        "Zero-Day Detection Rate": [
            97.84,
            np.nan,
            98.08
        ]
    })

    st.subheader(
        "Overall Performance"
    )

    st.dataframe(
        comparison_data.set_index("Model").style.format(
            "{:.2f}%"
        ),
        use_container_width=True
    )

    st.subheader("📊 Metric Comparison")

    chart_data = comparison_data.set_index("Model")[
        [
            "Accuracy",
            "Precision",
            "Recall",
            "F1-Score"
        ]
    ]

    # Convert percentage values to 0–100 scale if needed
    if chart_data.max().max() <= 1:
        chart_data = chart_data * 100

    st.bar_chart(
        chart_data,
        stack=False,
        height=420
    )

    st.subheader("🛡️ Simulated Zero-Day Detection")

    zero_day_chart = comparison_data.set_index("Model")[
        ["Zero-Day Detection Rate"]
    ].dropna()

    st.bar_chart(
        zero_day_chart,
        height=350
    )

    st.markdown(
        """
        **Interpretation:** This chart compares the detection rate
        for simulated held-out attack categories across the models.
        Higher values indicate more attacks detected in this experiment.
        """
    )

    st.caption(
        "Results are based on the UNSW-NB15 experimental evaluation. "
        "Zero-day detection refers to simulated held-out attack categories, "
        "not confirmed real-world zero-day attacks."
    )

    st.divider()

    st.subheader("🧠 Model Insights")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.info(
            "**Best Accuracy**\n\n"
            "Random Forest achieved 87.80% accuracy "
            "in the reported evaluation."
        )

    with col2:
        st.success(
            "**Highest Recall**\n\n"
            "Random Forest achieved 97.33% recall, "
            "indicating strong attack identification."
        )

    with col3:
        st.warning(
            "**False Positive Consideration**\n\n"
            "The reported Random Forest false positive "
            "rate is 23.87%. Some normal traffic may "
            "be flagged as suspicious."
        )

# ==================================================
# MODEL EVALUATION PAGE
# ==================================================

if selected_page == "📊 Model Evaluation":

    st.header("📊 Model Evaluation")

    st.write(
        "Evaluate and compare the performance of the trained "
        "machine learning models used in the Zero-Day Attack "
        "Detection System."
    )

    st.info(
        "The metrics below are based on the previously performed "
        "model evaluation."
    )

    # ----------------------------------------------
    # MODEL COMPARISON
    # ----------------------------------------------

    st.subheader("📈 Model Performance Comparison")

    evaluation_data = pd.DataFrame({
        "Model": [
            "Random Forest",
            "Isolation Forest",
            "Hybrid Detection"
        ],
        "Accuracy (%)": [87.80, 58.54, 85.54],
        "Precision (%)": [83.32, 82.30, 80.29],
        "Recall (%)": [97.33, 31.47, 97.72],
        "F1 Score (%)": [89.78, 45.54, 88.15],
        "False Positive Rate (%)": [23.87, 8.29, 29.39]
    })

    st.dataframe(
        evaluation_data,
        use_container_width=True,
        hide_index=True
    )

    st.subheader("📊 Accuracy, Precision, Recall and F1 Score")

    chart_data = evaluation_data.set_index("Model")[
        [
            "Accuracy (%)",
            "Precision (%)",
            "Recall (%)",
            "F1 Score (%)"
        ]
    ]

    st.bar_chart(
        chart_data,
        height=400
    )

    # ----------------------------------------------
    # HYBRID MODEL METRICS
    # ----------------------------------------------

    st.subheader("🛡️ Hybrid Detection Performance")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Accuracy", "85.54%")
    col2.metric("Precision", "80.29%")
    col3.metric("Recall", "97.72%")
    col4.metric("F1 Score", "88.15%")

    col1, col2 = st.columns(2)

    col1.metric("False Positive Rate", "29.39%")
    col2.metric("Simulated Zero-Day Detection", "98.08%")

    # ----------------------------------------------
    # CONFUSION MATRIX
    # ----------------------------------------------

    st.subheader("🔍 Hybrid Model Confusion Matrix")

    confusion_matrix_data = pd.DataFrame(
        [
            [26127, 10873],
            [1034, 44298]
        ],
        index=["Actual Normal", "Actual Attack"],
        columns=["Predicted Normal", "Predicted Attack"]
    )

    st.dataframe(
        confusion_matrix_data,
        use_container_width=True
    )

    st.bar_chart(
        confusion_matrix_data,
        height=350
    )

    st.caption(
        "TN = 26,127 | FP = 10,873 | FN = 1,034 | TP = 44,298"
    )

    # ----------------------------------------------
    # ZERO-DAY CATEGORY PERFORMANCE
    # ----------------------------------------------

    st.subheader("🚨 Simulated Zero-Day Attack Detection")

    zero_day_data = pd.DataFrame({
        "Attack Category": [
            "Exploits",
            "Reconnaissance",
            "Combined"
        ],
        "Detection Rate (%)": [
            98.21,
            97.65,
            98.08
        ]
    })

    st.dataframe(
        zero_day_data,
        use_container_width=True,
        hide_index=True
    )

    st.bar_chart(
        zero_day_data.set_index("Attack Category"),
        height=300
    )

    # ----------------------------------------------
    # INTERPRETATION
    # ----------------------------------------------

    st.subheader("📝 Evaluation Insights")

    st.success(
        "The hybrid model achieved a recall of 97.72%, "
        "indicating that it detected a high proportion of attacks "
        "in the evaluated dataset."
    )

    st.warning(
        "The false positive rate was 29.39%. This means some normal "
        "network traffic was incorrectly classified as an attack. "
        "Reducing false positives is an important area for improvement."
    )

    st.info(
        "The zero-day detection experiment simulated unseen attacks "
        "by excluding selected attack categories during training. "
        "The reported detection rate applies to this experimental "
        "setup and does not guarantee detection of every real-world "
        "zero-day attack."
    )
