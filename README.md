## 🧠 Project Overview — “Network Vulnerability Dashboard”

### 💡 What It Is

This is a **web-based dashboard** that helps you **see, understand, and track network vulnerabilities** easily.
Think of it like a “control panel” for your network scans — it collects results (like open ports, services, and targets) and shows them as **visual charts, summaries, and tables**.

Instead of digging through raw scan files, you get a clean dashboard view.

---

## 🧩 What It Does (Step-by-Step)

### 1. **Scanning Your Network**

* You (or an automated script) perform **vulnerability scans** using tools like **Nmap** or custom scanners.
* The scan results — like:

  * IP address / hostname (`target`)
  * Port number (`port`)
  * Service name (`service`)
  * Port state (e.g. `open`, `filtered`, `closed`)
  * Timestamp (when it was scanned)
* … are stored in a **SQLite database** called `vulns.db`.

So, this database becomes the “storage box” for all your scan results.

---

### 2. **Backend (Flask App)**

* Your backend is built using **Flask** — a lightweight Python web framework.
* Flask serves:

  * The HTML dashboard page
  * A REST API endpoint: `/api/rows`
    This endpoint sends all the scan data (from `vulns.db`) as JSON to the frontend.

Basically, Flask connects the **database (data)** and the **frontend (visuals)**.

---

### 3. **Frontend (Dashboard UI)**

* The frontend is pure **HTML + CSS + JavaScript**, no heavy frameworks.
* It fetches the scan data from `/api/rows` and shows:

  * ✅ **Summary cards:** quick overview (Total Hosts, Open Ports, etc.)
  * 📊 **Charts:** visualize your scan data

    * A pie chart of port states (`open`, `filtered`, etc.)
    * A bar chart of top 10 services
  * 📋 **Data table:** full detailed list of all scans

Everything updates dynamically once the data is fetched.

---

### 4. **Database (`vulns.db`)**

* It’s a small **SQLite** database (a lightweight database file, no server needed).
* Stores all vulnerability or scan data in a table — something like:

| id | target      | port | service | state    | timestamp  |
| -- | ----------- | ---- | ------- | -------- | ---------- |
| 1  | 192.168.1.1 | 80   | http    | open     | 2025-10-30 |
| 2  | 192.168.1.2 | 22   | ssh     | filtered | 2025-10-31 |

So it’s easy to store and fetch data without any complex setup.

---

## 🖥️ How It All Connects

Here’s the full flow in plain English:

```
[Scanner Tool] 
      ↓
   (saves data)
      ↓
 [vulns.db] — SQLite
      ↓
 [Flask Backend API]
      ↓
 [HTML Dashboard]
      ↓
 (Dynamic visual charts & table)
```

---

## ⚙️ What You Can Do With It

1. **See scan results instantly** on a web dashboard
2. **Track open / filtered ports** visually
3. **Identify top vulnerable services**
4. **Compare multiple scans over time** (if you log timestamps)
5. **Run it locally or host it** (on your server or GitHub Actions workflow)

---

## 🧩 Optional Add-ons (You Mentioned These)

You can enhance it with:

1. **Chart improvements** (we did that — now elegant and modern)
2. **GitHub Actions** — automatically scan and update dashboard daily
3. **Database auto-update** — merge scan files automatically
4. **Search / Filter UI** — to quickly find results in the table
5. **Authentication layer** — if you deploy it publicly

---

## 🎨 Aesthetic Summary

* **UI style:** Minimal, professional, dark glass aesthetic
* **Frameworks used:** Flask (backend), Bootstrap (layout), Chart.js + Plotly (charts)
* **Language stack:** Python, HTML, CSS, JavaScript, SQL (SQLite)
* **Files:**

  * `app.py` → Flask backend
  * `templates/index.html` → Dashboard UI
  * `vulns.db` → Database

---

## 🚀 In One Line

> “It’s a simple yet powerful vulnerability dashboard that turns raw scan data into a beautiful, interactive security report — all in your browser.”
