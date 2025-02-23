
# **Secure Data Hiding in Image Using Steganography**  
**by Mudunuri Shrilekha**

## 📌 **Overview**  
This project implements **steganography**, allowing users to hide encrypted messages within images while ensuring data security and stealth. Unlike traditional encryption, which signals the presence of hidden data, this tool conceals information seamlessly within digital content. 

The .pptx file has all the details about the project. 
The sample image used for the results shown in the PPT file are also in this repository.

## 🔥 **Features**  
✅ **Dual-Layer Security:** Encrypts messages before embedding for extra protection.  
✅ **Adaptive Image Processing:** Prevents overflow while maintaining image quality.  
✅ **Smart Error Handling:** Validates inputs, detects compatibility issues, and suggests fixes.  
✅ **Cross-Platform Compatibility:** Works on **Windows, macOS, and Linux**.  
✅ **User-Friendly Interface:** Professional UI with real-time feedback.  
✅ **Modular & Extensible:** Well-structured codebase for easy enhancements.  

## 🚀 **Installation**  
### **Requirements**  
- Python 3.x  
- Required libraries (install via pip)  
 

### **1️⃣ Install Python (if not installed)**  
- Download **Python 3.x** from [Python.org](https://www.python.org/downloads/) and install it.  
- Verify installation by running:  
  ```bash
  python --version
  ```

### **2️⃣ Install Required Libraries**  
Run the following command in the **terminal/command prompt**:  
```bash
pip install cryptography opencv-python
```

### **3️⃣ Verify Installation**  
To ensure everything is installed correctly, open **IDLE** and run:  
```python
import cv2
import cryptography
import tkinter

print(cv2.__version__)  # Should display OpenCV version
```

---

## ▶️ **Running the Project in IDLE**  
### **1️⃣ Open IDLE and Load the Script**  
- Open **IDLE** (Python’s built-in editor).  
- Click **File > Open** and select **`proj.py`**.  

### **2️⃣ Run the Code**  
- Click **Run > Run Module** (or press `F5`).  

---

## ⚙️ **Configuration**  
- Supports multiple image formats: PNG, JPEG, BMP  
- Adjustable encryption settings for enhanced security  
- Custom error handling for improved user experience  

## 🛠 **Future Enhancements**  
- **Audio/Video Steganography**: Expanding beyond images.  
- **Real-time Messaging Support**: Secure communication channels.  
- **Advanced Steganalysis Resistance**: Improved detection prevention.  

## 💡 **Contributing**  
Contributions are welcome! Open an issue or submit a pull request to improve the project.  
