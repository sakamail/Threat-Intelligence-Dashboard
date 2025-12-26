Sure 🙂
Below is the **English version of the README.md**, ready to be used directly on GitHub.

---

# 🧬 Threat Intelligence Dashboard

A web application for **URL threat analysis** using the **VirusTotal API**, with interactive visualizations and a modern dashboard UI.

This project demonstrates working with external security APIs, backend development with Flask, threat intelligence data processing, and data visualization using Plotly.

---

## 🚀 Features

* URL scanning via **VirusTotal API v3**
* Automatic URL submission if no report exists
* Custom **Trust Score (0–100)** calculation based on:

  * malicious & suspicious detections
  * community votes
  * VirusTotal reputation score
* Interactive visualizations:

  * Detection donut chart
  * Threat radar chart
  * Trust score gauge
  * Community votes chart
* Detailed metadata display:

  * final URL & TLD
  * tags, categories, threat names
  * submission timeline
* Full VirusTotal JSON response viewer
* Clean dark-themed UI using Plotly.js

---

## 🛠 Tech Stack

### Backend

* **Python 3**
* **Flask** — web framework
* **Requests** — HTTP client
* **python-dotenv** — environment variables
* **VirusTotal API v3**

### Frontend

* **HTML5**
* **CSS (custom dark UI)**
* **Jinja2 templates**
* **Plotly.js** — interactive charts

### Visualization

* **plotly.graph_objects**
* Donut charts
* Radar charts
* Gauge / Indicator charts

---

## 📚 What I Learned

* Working with **Threat Intelligence APIs (VirusTotal)**
* URL submission and report polling logic
* Base64 URL encoding for VirusTotal IDs
* Backend design for security analysis workflows
* Parsing and aggregating complex JSON responses
* Designing a custom **Trust Score** metric
* Integrating Plotly (Python → JSON → JavaScript)
* Flask → Jinja → JavaScript data flow
* Building security dashboards
* Environment variable management for API keys
* Error handling and API rate-limit awareness

---

## ⚙️ Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-username/threat-intelligence-dashboard.git
cd threat-intelligence-dashboard
```

### 2. Install dependencies

```bash
pip install flask requests python-dotenv plotly
```

### 3. Get a VirusTotal API Key

1. Sign up at [https://www.virustotal.com](https://www.virustotal.com)
2. Copy your **API Key**

### 4. Create a `.env` file

```env
VT_API_KEY=your_virustotal_api_key_here
```

### 5. Run the application

```bash
python app.py
```

Open in your browser:

```
http://127.0.0.1:5000
```

---

## 🧪 Example Usage

1. Enter a URL, for example:

```
https://example.com
```

2. Click **Analyze**
3. The application will:

   * submit the URL to VirusTotal if needed
   * retrieve the analysis report
   * calculate the Trust Score
   * render interactive charts and metadata

---

## 📊 Trust Score Logic

The Trust Score is calculated as follows:

* −20 points per **malicious** detection
* −10 points per **suspicious** detection
* −5 points per **malicious** community vote
* +2 points per **harmless** community vote
* +VirusTotal **reputation score**

Final score is clamped between **0 and 100**.

---

## 📁 Project Structure

```
.
├── app.py              # Flask backend
├── templates/
│   └── scanner.html    # UI + Plotly.js
├── .env                # API key (not committed)
└── README.md
```

---

## 🔐 Security Notes

* API keys are stored in `.env`
* Add `.env` to `.gitignore`
* This project is intended for **educational and research purposes only**

---

## 📌 Possible Improvements

* Asynchronous processing (async / Celery)
* Result caching
* File and IP address analysis
* User authentication
* Scan history
* Docker support

---

## 🧑‍💻 Author

Built as a learning and research project
focused on **Threat Intelligence, Flask, and Data Visualization**

---


