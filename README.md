Absolutely ✅ — here’s a clean and professional **README.md** tailored for your `vul-dashboard` project.
It explains setup, usage, GitHub Actions automation, and troubleshooting clearly.

---

### 🧠 **README.md**

```markdown
# 🔒 Vulnerability Dashboard

A simple Flask-based web dashboard that visualizes network vulnerability scan results collected using Nmap and stored in SQLite.

---

## 🚀 Features

- Automated vulnerability scanning with **Nmap**
- Real-time visualization of open and filtered ports
- GitHub Actions CI/CD automation
- SQLite backend for scan history
- REST API for data and charts
- Responsive dark-themed dashboard

---

## 🧩 Project Structure

```

vul-dashboard/
│
├── app.py                  # Flask web app
├── nmap_scan.py            # Nmap scan script
├── templates/
│   └── index.html          # Dashboard frontend
├── static/
│   └── style.css           # (Optional) Custom CSS
├── vulns.db                # SQLite database (auto-created)
├── .github/
│   └── workflows/
│       └── scan.yml        # GitHub Actions automation
└── README.md               # Project documentation

````

---

## ⚙️ Setup Instructions

### 1️⃣ Clone the repository
```bash
git clone https://github.com/<your-username>/vul-dashboard.git
cd vul-dashboard
````

### 2️⃣ Create a virtual environment

```bash
python -m venv venv
source venv/bin/activate   # (Linux/Mac)
venv\Scripts\activate      # (Windows)
```

### 3️⃣ Install dependencies

```bash
pip install -r requirements.txt
```

If `requirements.txt` doesn’t exist, install manually:

```bash
pip install flask python-nmap
```

---

## 🧠 Usage

### 1️⃣ Run a local scan

```bash
python nmap_scan.py
```

This will run Nmap and store results into `vulns.db`.

### 2️⃣ Start the dashboard

```bash
python app.py
```

Then open your browser:

```
http://127.0.0.1:5000
```

You’ll see the **Vulnerability Dashboard** showing scan results.

---

## ⚡ GitHub Actions Automation

This project includes a workflow that automatically:

1. Runs a vulnerability scan
2. Updates the SQLite database
3. Commits and pushes the new results

To enable it:

1. Go to **Repository Settings → Actions → General → Workflow Permissions**
2. Select:

   * ✅ *Read and write permissions*
   * ✅ *Allow GitHub Actions to create and approve pull requests*

---

## 🧰 API Endpoints

| Endpoint          | Description                                          |
| ----------------- | ---------------------------------------------------- |
| `/api/rows`       | Returns latest scan entries as JSON                  |
| `/api/chart-data` | Returns aggregated chart data (by service and state) |

---

## 🔧 Troubleshooting

### ❌ “no such column: status”

You’re using an old database schema.
Fix it by deleting the old file and letting the app recreate it:

```bash
rm vulns.db
python nmap_scan.py
```

### ❌ Merge conflict on `vulns.db`

Since the DB changes frequently, ignore it in git:

```bash
echo "vulns.db" >> .gitignore
git rm --cached vulns.db
git add .gitignore
git commit -m "ignore vulns.db"
git push origin main
```

---

## 🧑‍💻 Author

**SecureWithMedhavi-UX**
GitHub: [@securewithmedhavi-ux](https://github.com/securewithmedhavi-ux)

---

## 📜 License

This project is licensed under the **MIT License**.
Feel free to modify and use it for your own projects.

```

---

Would you like me to include a **`requirements.txt`** file too (so setup is one command)?  
It would contain Flask, python-nmap, and a few helpers.
```
