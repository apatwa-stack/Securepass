# Step-by-Step Guide: Uploading SecurePass to HSO EduGit & Inviting Your Professor

This guide walks you through every single step to upload your project to the Hochschule Offenburg EduGit platform ([https://edugit.hs-offenburg.de](https://edugit.hs-offenburg.de)) and invite your professor as a **"Reporter"**.

---

## Step 1: Initialize Git and Commit Your Code Locally

Open PowerShell in your project folder (`C:\Users\Anup\OneDrive\Desktop\Securepass`) and run:

```powershell
# 1. Initialize git repository
git init

# 2. Configure your identity (replace with your HSO name & email)
git config user.name "Your Name"
git config user.email "your.email@hs-offenburg.de"

# 3. Add all files to staging
git add .

# 4. Commit the project
git commit -m "Initial commit: SecurePass cryptographic password service with C-native entropy engine and REST API"
```

---

## Step 2: Create a Project on HSO EduGit

1. Open your browser and navigate to: **[https://edugit.hs-offenburg.de](https://edugit.hs-offenburg.de)**.
2. Log in using your Hochschule Offenburg university credentials (same as your campus account / Moodle).
3. In the top bar or dashboard, click the **"+"** button (or **"New project"** / **"Create project"**).
4. Select **"Create blank project"**.
5. Fill in the details:
   - **Project name**: `SecurePass` (or `password-service`)
   - **Project URL / Namespace**: select your personal username
   - **Visibility Level**: Choose **Private** (recommended for academic assignments so other students cannot copy) or **Internal**.
   - **Project Configuration**: **Uncheck** "Initialize repository with a README" (since we already have a complete README in our code).
6. Click **"Create project"**.

---

## Step 3: Push Your Code to EduGit

Once your project is created on EduGit, copy the repository HTTPS URL (e.g., `https://edugit.hs-offenburg.de/<your-username>/SecurePass.git`).

In your PowerShell terminal, run:

```powershell
# 1. Set main as default branch
git branch -M main

# 2. Add EduGit as your remote origin (replace with YOUR repository URL)
git remote add origin https://edugit.hs-offenburg.de/<your-username>/SecurePass.git

# 3. Push your code to EduGit
git push -u origin main
```
*(Git will prompt you for your EduGit username and password/personal access token. Enter your HSO credentials).*

---

## Step 4: Invite Your Professor as "Reporter"

To allow your professor to review and grade your private repository without making it public:

1. In your project on EduGit, look at the left sidebar menu.
2. Click on **"Manage"** (or **"Project information"** / **"Members"** depending on the GitLab version).
3. Click on **"Members"**.
4. Click the blue button: **"Invite members"**.
5. In the modal:
   - **Username or email address**: Search for your professor's name or university email address.
   - **Select a role**: Choose **"Reporter"** from the dropdown menu (as explicitly requested in the assignment).
   - **Access expiration date**: Leave blank (or set after end of semester).
6. Click **"Invite"**.
   - You will see the professor listed under Project Members with the role **Reporter**.

---

## Step 5: Submit to Moodle

1. Copy your repository link:
   `https://edugit.hs-offenburg.de/<your-username>/SecurePass`
2. Open your course on Moodle.
3. Locate the corresponding assignment task.
4. Submit:
   - **Your repository link** (pasted into the submission text or comment field).
   - **Your PDF Report** (attach the generated 3-5 page report from `report/SecurePass_Academic_Report.pdf` or `report/REPORT.md`).
