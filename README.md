# 🔧 Reverse Engineering KPG-202D (Kenwood ProTalk TK-3701D)

## 📖 Introduction
This was my first time reverse engineering on this scale.  
The goal: unlock and change settings on my second-hand **Kenwood ProTalk TK-3701D**, where the previous owner had lost the password.  

What started as a small summer project quickly became a deep dive into reverse engineering. But im glad I did it, learned a lot from it.  

> ⚡ Special thanks to:  
> - My Lithuanian friend [Luke](https://github.com/DeprecatedLuke) for introducing me to reverse engineering and getting me started  
> - Peter and Mark for testing and verifying patches  

---

## 🛠️ Tools Used
- [x32dbg](https://x64dbg.com/) → debugging, patching, stepping  
- [Cheat Engine](https://cheatengine.org/) → memory scanning, quick testing  
- [Binary Ninja](https://binary.ninja/) → disassembly & code analysis  
- **PowerShell** → experimenting with hidden features  
- **Registry Editor (regedit)** → checking KPG-202D license & keys  

---

## 🚀 Steps

### 1️⃣ MCF application & PowerShell
- Luke discovered the program is an **MCF app** and gave me a few pointers.  
- Wrote a [PowerShell script](https://github.com/JesperKuipers/KPG-202D/blob/master/Reset_Password-KPG202D.ps1) that opened a hidden feature called **Password reset execution**, but it was password protected (and is not needed in final exe)  

---

### 2️⃣ Hidden features & license key
- Suspected more hidden features, maybe even a **dealer mode**  
- Explored the registry:  ```Computer\HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\JVC KENWOOD Corporation\KPG-202D```
  - Tried changing the license key checks in registry → led to a password screen<br><img width="343" height="200" alt="password screen image" src="https://github.com/user-attachments/assets/7ae95b1f-b85a-4daa-ba63-6bf1be216052" />
- [**Release v1**](https://github.com/JesperKuipers/KPG-202D/releases/tag/exe) = patched piracy protection, is still password-locked but doesn't throw an error when changing the license key in registry  

---

### 3️⃣ Breaking into the password dialog
> This step alone took ~**100 hours** 😅  

- Placed a **breakpoint on `MessageBoxW`**, then entered a wrong password  
- Stepped out & used the call trace → found the password check code  
- First patch removed the error dialog but stopped execution → useless ([Release v2.0](https://github.com/JesperKuipers/KPG-202D/releases/tag/exe))  
- Tried forcing if-statements → new dialog popped up (still useless) <br> <img width="343" height="195" alt="image" src="https://github.com/user-attachments/assets/85f5b2a5-18a2-4816-8e63-51603f81e6bb" />
- Finally found the correct patch → **any password accepted** 🎉 ([Release v2.5](https://github.com/JesperKuipers/KPG-202D/releases/tag/exe))  

Realization:  
- Either there is no dealer mode, or it’s like finding a needle in a haystack

✅ Could now **use software** with alterd license key in registry  

---

### 4️⃣ Reading the radio settings
- Same approach for [3️⃣ Breaking into the password dialog](#3%EF%B8%8F⃣-breaking-into-the-password-dialog)
- Breakpoint on `MessageBoxW` + patching password check  
- At first only worked after **3 wrong attempts**<br> ![reading porto](https://github.com/user-attachments/assets/ff1a1d50-7f0f-4b47-9e75-0b1aaad21135)
- After few more patches → worked after any password attempt ([Release v3](https://github.com/JesperKuipers/KPG-202D/releases/tag/exe))  

✅ Could now **read locked radios**  

---

### 5️⃣ Writing to the radio
- Writing uses a different password check then [4️⃣ Reading the radio settings](#4%EF%B8%8F⃣-reading-the-radio-settings), but repeated the same patching process  
- While I made relase v4, Marc discovered that reading a locked radio with Release v3 shows the read password
  - See [📘 How to use final exe](#-how-to-use-final-exe) for Marc’s password extraction method     
(for us read & write password was `43778`) <br><img width="718" height="152" alt="image" src="https://github.com/user-attachments/assets/40b8b7e6-29db-4406-a089-be6d6e57786d" />
- [**Release v4**](https://github.com/JesperKuipers/KPG-202D/releases/tag/exe) accepts any password (or blank) for **both read & write**  
  - Writing default settings to radio removes password 

✅ Could now **read & write locked radios** and **find read password** 

---

## 📥 Installation
⚠️ **Disclaimer:** I do **not** condone piracy.  

To use:  
1. Install official KPG-202D  
2. Enter a valid license key  
3. Replace the installed `KPG202D.exe` in `C:\Program Files (x86)\Kenwood Fpu\KPG-202D` with the patched release of your choice
> [VirusTotal results](https://www.virustotal.com/gui/file/6b7d32bc713478e32095e2715c44be6da2a6b481da232fbc34822f8fbf4c098a/detection) (score 1/71, its a false postive)  

---

## 📘 How to Use (final exe)
### A Read & Write
- With last release you can now **read & write** to any locked Kenwood ProTalk TK-3701D
- Removing password from the radio (writing default settings to locked radio)
### B Get Read Password
- **Why?** Because people often reuse the same password across multiple radios or even for read & write 🚨 
- If you want the password read the radio using my modified exe, then use the print preview feature <br>![find password](https://github.com/user-attachments/assets/cb7e7d73-3c1e-4c50-88b2-b2f82c20aa6e)

 
---

## 🏁 Conclusion
- From **KPG-6 → KPG-202D**, all Kenwood programming tools share the same codebase, slightly modified per model:  
  - Comparing **KPG-171D** and **KPG-202D** shows near-identical structure  
  - Multiple references to **KPG-6** exist inside the binary
- The project took way to long, but learned a lot about reverse engineering   

👉 I’m confident this process can be repeated for most Kenwood programming tools  
💡 If you need help adapting this for another Kenwood program, feel free to open an [**Issue**](https://github.com/JesperKuipers/KPG-202D/issues/new)  

---

## 📜 License

This project is licensed under the **Creative Commons Attribution-NonCommercial-NoDerivatives 4.0 International (CC BY-NC-ND 4.0)** license.  
That means you are free to use and share the provided information and executables for personal, non-commercial purposes, but you are **not allowed** to modify or redistribute derivative versions.

➡️ For the full license text, see [CC-BY-NC-ND-4.0.md](./CC-BY-NC-ND-4.0.md).
