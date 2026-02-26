# Maktabkhooneh Downloader (PyQt5)

A modern desktop downloader for Maktabkhooneh courses, built with Python + PyQt5.

یک برنامه دسکتاپ مدرن برای دانلود دوره‌های مکتب‌خونه با Python و PyQt5.

---

## English

### Overview
This project provides a GUI application to download course videos (and related resources) from Maktabkhooneh with a simple workflow.

### Features
- Single-course and multi-course download modes
- Dynamic bulk URL list (`+ add link`, remove rows)
- Login/session management (email/mobile + password)
- Reuse stored session from `session.json`
- Download progress logs with inline updates
- Optional sample download (`Sample bytes`)
- Scheduled downloads:
  - Start time
  - End time (auto-stop when reached)
- Optional system shutdown after successful completion
- Modern UI with Light/Dark theme switch
- Course attachments and subtitle download (when available)

### Project Files
- `maktab.py`: Main GUI + downloader logic
- `maktab-gui.py`: App launcher
- `session.json`: Stored login session (generated at runtime)

### Requirements
- Python 3.10+
- `PyQt5`
- `requests`

Install dependencies:

```bash
pip install PyQt5 requests
```

### Run

```bash
python maktab-gui.py
```

or

```bash
python maktab.py
```

### Build Executable (PyInstaller)

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name MaktabDownloader maktab-gui.py
```

Output binary will be created in `dist/`.

### Usage Notes
- Enter valid Maktabkhooneh course URLs (`https://maktabkhooneh.org/course/...`).
- For paid/private content, a valid account/session is required.
- Respect platform terms of service and content ownership rules.

### Troubleshooting
- If login fails, try enabling `Force login` and re-enter credentials.
- If downloads are skipped with source-not-found, enable `Verbose log` and review generated debug info.
- On Linux/macOS, system shutdown may require proper permissions.

---

## فارسی

### معرفی
این پروژه یک اپلیکیشن گرافیکی برای دانلود دوره‌های مکتب‌خونه است که با رابط کاربری ساده، فرآیند دانلود را سریع و قابل مدیریت می‌کند.

### امکانات
- دانلود تک‌دوره‌ای و چنددوره‌ای
- حالت دانلود دست‌جمعی با افزودن لینک‌های جداگانه (`+ افزودن لینک`)
- مدیریت لاگین و سشن (ایمیل/موبایل + پسورد)
- استفاده مجدد از سشن ذخیره‌شده در `session.json`
- نمایش لاگ پیشرفت دانلود به‌صورت آپدیت خطی
- امکان دانلود نمونه‌ای با `Sample bytes`
- دانلود زمان‌بندی‌شده:
  - زمان شروع
  - زمان پایان (توقف خودکار در زمان تعیین‌شده)
- گزینه خاموش کردن سیستم پس از اتمام موفق
- رابط کاربری مدرن با تم روشن/تیره (Dark Mode)
- دانلود زیرنویس و فایل‌های ضمیمه (در صورت وجود)

### ساختار فایل‌ها
- `maktab.py`: منطق اصلی برنامه + رابط گرافیکی
- `maktab-gui.py`: فایل لانچر برنامه
- `session.json`: فایل سشن لاگین (در زمان اجرا ساخته می‌شود)

### پیش‌نیازها
- Python 3.10 یا بالاتر
- `PyQt5`
- `requests`

نصب وابستگی‌ها:

```bash
pip install PyQt5 requests
```

### اجرا

```bash
python maktab-gui.py
```

یا:

```bash
python maktab.py
```

### ساخت فایل اجرایی (PyInstaller)

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --name MaktabDownloader maktab-gui.py
```

فایل نهایی داخل پوشه `dist/` ساخته می‌شود.

### نکات استفاده
- لینک دوره باید معتبر باشد (`https://maktabkhooneh.org/course/...`).
- برای دوره‌های پولی/خصوصی باید حساب کاربری معتبر داشته باشید.
- استفاده از ابزار باید مطابق قوانین پلتفرم و حقوق محتوا باشد.

### رفع اشکال
- اگر لاگین انجام نشد، `Force login` را فعال کنید و دوباره وارد شوید.
- اگر لینک ویدیو پیدا نشد، `Verbose log` را فعال کنید و خروجی دیباگ را بررسی کنید.
- در لینوکس/مک، خاموش کردن سیستم ممکن است نیاز به دسترسی مناسب داشته باشد.

---

## Author
- GitHub: [@Mtgama](https://github.com/Mtgama)
