# ⛈️ Badal — Cloud Vulnerability Analyser

**Badal** (Cloud) is an advanced security orchestration tool designed to provide deep visibility into AWS infrastructure. It goes beyond simple resource listing by analyzing software vulnerabilities, mapping complex dependencies, and leveraging AI to provide actionable remediation steps.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.9+-blue.svg)
![FastAPI](https://img.shields.io/badge/framework-FastAPI-green.svg)
![AWS](https://img.shields.io/badge/cloud-AWS-orange.svg)

---

## 🚀 Key Features

### 🔍 Deep Infrastructure Scanning
*   **Compute (EC2):** Scans OS-level packages (via AWS SSM) to identify outdated or vulnerable software.
*   **Serverless (Lambda):** Analyzes runtimes, layers, and `requirements.txt` dependencies within function code.
*   **Storage & Database:** Inspects S3 buckets and RDS instances for configuration risks.
*   **Identity (IAM):** Evaluates roles and policies for "Least Privilege" violations.

### 🛡️ Vulnerability Intelligence
*   **NVD Integration:** Real-time lookup of CVEs (Common Vulnerabilities and Exposures) using the National Vulnerability Database API.
*   **Risk Scoring:** Dynamic risk calculation (0.0 - 1.0) based on CVSS scores, resource exposure, and configuration flaws.

### 🕸️ Dependency Graphing
*   **Visual Topology:** Generates a directed graph (`dependency_graph.png`) showing how resources interact.
*   **Bottleneck Detection:** Automatically identifies **Single Points of Failure** and **Circular Dependencies** that could lead to outages or security cascades.

### ✨ AI-Driven Remediation
*   **Gemini AI Integration:** Sends structured scan reports to Google Gemini 1.5 Flash to generate a human-readable security audit.
*   **Instant Fixes:** Provides exact **AWS CLI commands** to patch vulnerabilities immediately.

---

## 🛠️ Tech Stack

-   **Backend:** FastAPI (Python 3.9+)
-   **Cloud SDK:** Boto3 (AWS SDK for Python)
-   **AI:** Google Gemini 1.5 Flash API
-   **Data Science:** NetworkX (Graph theory), Matplotlib (Visualization)
-   **Frontend:** Vanilla JS / CSS3 (Glassmorphism UI)
-   **Auth:** JWT (JSON Web Tokens) & AWS IAM

---

## 📦 Installation & Setup

### Prerequisites
- Python 3.9 or higher
- An AWS Account with appropriate permissions (ReadOnlyAccess + SSM permissions for deep scans)
- A [Google Gemini API Key](https://aistudio.google.com/app/apikey)

### Local Setup
1.  **Clone the repository:**
    ```bash
    git clone https://github.com/yourusername/badalJaldiKaro.git
    cd badalJaldiKaro
    ```

2.  **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

3.  **Configure environment variables:**
    Create a `.env` file in the root directory:
    ```env
    GEMINI_API_KEY=your_gemini_api_key_here
    JWT_SECRET=your_random_secret_string
    ```

4.  **Run the application:**
    ```bash
    python app.py
    ```
    The dashboard will be available at `http://localhost:8000`.

### Docker Setup
```bash
docker build -t badal .
docker run -p 8000:8000 --env-file .env badal
```

---

## 🖥️ Usage Guide

1.  **Login:** Enter your AWS Access Key, Secret Key, and preferred Region. Badal uses these to generate a temporary session; credentials are never stored on the server.
2.  **Scan:** Click "Authenticate & Connect". Badal will begin traversing your AWS environment.
3.  **Analyze:** 
    *   View the **Resources** tab for a breakdown of every service.
    *   Check the **Dependency Graph** to see how your architecture is connected.
    *   Open the **Bottlenecks** tab to see where your infrastructure is fragile.
4.  **AI Analysis:** Navigate to the **AI Analysis ✨** tab and click "Run AI Analysis". Review the prioritized list of problems and copy the CLI commands to your terminal to fix them.

---

## 📁 Project Structure

```text
├── app.py                # FastAPI server & API routing
├── badal/
│   ├── badal.py          # Core scanning & analysis engine
│   └── solution_provider.py # Gemini AI integration logic
├── login/
│   └── loginJaldiKaro.py # AWS Auth & JWT management
├── frontend/             # Dashboard UI (HTML/CSS/JS)
├── Dockerfile            # Container configuration
└── requirements.txt      # Python dependencies
```

---

## ⚠️ Security Note
Badal requires AWS credentials to function. It is recommended to use an IAM user with `ReadOnlyAccess` for general scans. To enable EC2 package scanning, the instances must have the **AmazonSSMManagedInstanceCore** policy attached and the SSM Agent installed.

---

## 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.
