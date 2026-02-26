#!/usr/bin/env python3
import json
import platform
import re
import subprocess
import sys
import time
import traceback
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urljoin, urlparse

import requests
from requests.utils import requote_uri
from PyQt5.QtCore import QDate, QThread, QTime, Qt, pyqtSignal
from PyQt5.QtGui import QTextCursor
from PyQt5.QtWidgets import (
    QApplication,
    QCheckBox,
    QDateEdit,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QSpinBox,
    QTimeEdit,
    QVBoxLayout,
    QWidget,
)

ORIGIN = "https://maktabkhooneh.org"
UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125 Safari/537.36"


def sanitize_name(name: str) -> str:
    name = re.sub(r'[\\/:*?"<>|]', " ", name or "")
    name = re.sub(r"[\s\u200c\u200f\u202a\u202b]+", " ", name).strip()
    return (name or "untitled")[:150]


def decode_html_entities(text: str) -> str:
    return (
        text.replace("&amp;", "&")
        .replace("&quot;", '"')
        .replace("&#39;", "'")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
    )


def extract_course_slug(course_url: str) -> str:
    parsed = urlparse(course_url)
    if parsed.netloc != "maktabkhooneh.org":
        raise ValueError("دامنه لینک باید maktabkhooneh.org باشد")
    parts = [p for p in parsed.path.split("/") if p]
    if "course" not in parts:
        raise ValueError("آدرس دوره معتبر نیست")
    idx = parts.index("course")
    if idx + 1 >= len(parts):
        raise ValueError("slug دوره از لینک قابل استخراج نیست")
    return parts[idx + 1]


def _add_video_candidates(pool: list[str], seen: set[str], candidates: list[str]) -> None:
    for raw in candidates:
        if not raw:
            continue
        url = decode_html_entities(raw).replace("\\/", "/").strip()
        if "/videos/" not in url and ".m3u8" not in url and ".mp4" not in url:
            continue
        if url.startswith("//"):
            url = "https:" + url
        elif url.startswith("/"):
            url = urljoin(ORIGIN, url)
        if url not in seen:
            seen.add(url)
            pool.append(url)


def extract_video_sources(html: str) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    _add_video_candidates(out, seen, re.findall(r'<source\b[^>]*?src=["\']([^"\'>]+)["\']', html, flags=re.I))
    _add_video_candidates(out, seen, re.findall(r'<video\b[^>]*?src=["\']([^"\'>]+)["\']', html, flags=re.I))
    _add_video_candidates(out, seen, re.findall(r'data-src=["\']([^"\']+)["\']', html, flags=re.I))
    _add_video_candidates(
        out,
        seen,
        re.findall(r'["\'](https?:\\?/\\?/[^"\']*(?:videos|m3u8)[^"\']*)["\']', html, flags=re.I),
    )
    _add_video_candidates(
        out,
        seen,
        re.findall(r'["\'](/[^"\']*(?:videos|m3u8)[^"\']*)["\']', html, flags=re.I),
    )
    return out


def pick_best_source(urls: list[str]) -> str | None:
    if not urls:
        return None
    for u in urls:
        if u.lower().endswith(".mp4"):
            return u
    for u in urls:
        if re.search(r"/videos/hq\\d+", u) or "/videos/hq" in u:
            return u
    for u in urls:
        if ".m3u8" in u.lower():
            return u
    return urls[0]


def extract_track_links(html: str) -> list[str]:
    links = re.findall(r'<track\b[^>]*?src=["\']([^"\'>]+)["\']', html, flags=re.I)
    return list(dict.fromkeys(links))


def extract_attachment_links(html: str) -> list[str]:
    blocks = re.findall(
        r'<div[^>]*class=["\'][^"\']*unit-content--download[^"\']*["\'][^>]*>[\s\S]*?</div>',
        html,
        flags=re.I,
    )
    links: list[str] = []
    seen = set()
    for block in blocks:
        for href in re.findall(r'<a[^>]+href=["\']([^"\'>]+)["\']', block, flags=re.I):
            if "attachments" in href.lower() and href not in seen:
                seen.add(href)
                links.append(href)
    return links


def cookie_string_from_session(session: requests.Session) -> str:
    csrftoken = session.cookies.get("csrftoken", domain="maktabkhooneh.org") or session.cookies.get("csrftoken")
    sessionid = session.cookies.get("sessionid", domain="maktabkhooneh.org") or session.cookies.get("sessionid")
    if not csrftoken or not sessionid:
        return ""
    return f"csrftoken={csrftoken}; sessionid={sessionid}"


def apply_cookie_string(session: requests.Session, cookie_text: str) -> None:
    items = [s.strip() for s in cookie_text.split(";") if "=" in s]
    for item in items:
        key, value = item.split("=", 1)
        session.cookies.set(key.strip(), value.strip(), domain="maktabkhooneh.org", path="/")


def safe_uri(value: str) -> str:
    return requote_uri(value)


def format_bytes(num: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    n = float(num)
    idx = 0
    while n >= 1024 and idx < len(units) - 1:
        n /= 1024.0
        idx += 1
    if idx == 0:
        return f"{int(n)} {units[idx]}"
    if n >= 100:
        return f"{n:.0f} {units[idx]}"
    if n >= 10:
        return f"{n:.1f} {units[idx]}"
    return f"{n:.2f} {units[idx]}"


def text_progress_bar(ratio: float, width: int = 22) -> str:
    ratio = max(0.0, min(1.0, ratio))
    filled = int(round(ratio * width))
    return "█" * filled + "░" * (width - filled)


@dataclass
class DownloadConfig:
    course_urls: list[str]
    save_dir: Path
    email: str
    password: str
    sample_bytes: int
    verbose: bool
    force_login: bool
    start_ts: float | None
    end_ts: float | None


class DownloaderThread(QThread):
    log = pyqtSignal(str)
    done = pyqtSignal(bool, str)

    def __init__(self, config: DownloadConfig) -> None:
        super().__init__()
        self.config = config
        self._stop_requested = False
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": UA})

    def stop(self) -> None:
        self._stop_requested = True

    def _emit(self, text: str) -> None:
        self.log.emit(text)

    def _check_stop(self) -> None:
        if self._stop_requested:
            raise InterruptedError("دانلود متوقف شد")
        if self.config.end_ts is not None and time.time() >= self.config.end_ts:
            raise InterruptedError("بازه زمانی دانلود تمام شد")

    def _debug(self, text: str) -> None:
        if self.config.verbose:
            self._emit(f"[VERBOSE] {text}")

    def _wait_for_schedule_start(self) -> None:
        if self.config.start_ts is None:
            return
        while True:
            self._check_stop()
            now = time.time()
            if now >= self.config.start_ts:
                self._emit("[INFO] زمان شروع دانلود رسید")
                return
            remain = int(self.config.start_ts - now)
            self._emit(f"[INFO] در انتظار شروع زمان‌بندی‌شده... {remain} ثانیه")
            self.msleep(1000)

    def _session_path(self) -> Path:
        return self.config.save_dir / "session.json"

    def _read_session_file(self) -> dict[str, Any]:
        p = self._session_path()
        if not p.exists():
            return {"users": {}, "lastUsed": ""}
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            return {"users": {}, "lastUsed": ""}

    def _write_session_file(self, email_key: str, cookie: str, old_data: dict[str, Any]) -> None:
        data = old_data if isinstance(old_data, dict) else {"users": {}, "lastUsed": ""}
        users = data.setdefault("users", {})
        users[email_key] = {"cookie": cookie}
        data["lastUsed"] = email_key
        self._session_path().write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

    def _core_data(self) -> dict[str, Any]:
        r = self.session.get(f"{ORIGIN}/api/v1/general/core-data/?profile=1", timeout=30)
        r.raise_for_status()
        return r.json()

    def _is_authenticated(self) -> bool:
        try:
            core = self._core_data()
            return bool(core.get("auth", {}).get("details", {}).get("is_authenticated"))
        except Exception:
            return False

    def _login(self, email: str, password: str) -> None:
        self._emit("[INFO] در حال لاگین...")
        self.session.get(f"{ORIGIN}/accounts/login/", timeout=30)
        csrftoken = self.session.cookies.get("csrftoken")
        if not csrftoken:
            core = self._core_data()
            csrftoken = core.get("auth", {}).get("csrf") or self.session.cookies.get("csrftoken")
        if not csrftoken:
            raise RuntimeError("CSRF token دریافت نشد")

        headers = {
            "X-Requested-With": "XMLHttpRequest",
            "X-CSRFToken": csrftoken,
            "Origin": ORIGIN,
            "Referer": f"{ORIGIN}/accounts/login/",
        }

        r1 = self.session.post(
            f"{ORIGIN}/api/v1/auth/check-active-user",
            data={"csrfmiddlewaretoken": csrftoken, "tessera": email, "g-recaptcha-response": ""},
            headers=headers,
            timeout=30,
        )
        r1.raise_for_status()
        j1 = r1.json()
        if j1.get("status") != "success":
            raise RuntimeError(f"check-active-user failed: {j1}")

        r2 = self.session.post(
            f"{ORIGIN}/api/v1/auth/login-authentication",
            data={
                "csrfmiddlewaretoken": csrftoken,
                "tessera": email,
                "hidden_username": email,
                "password": password,
                "g-recaptcha-response": "",
            },
            headers=headers,
            timeout=30,
        )
        r2.raise_for_status()
        j2 = r2.json()
        if j2.get("status") != "success":
            raise RuntimeError(f"login-authentication failed: {j2}")
        if not self._is_authenticated():
            raise RuntimeError("لاگین انجام شد ولی احراز هویت تایید نشد")

    def _prepare_session(self) -> None:
        data = self._read_session_file()
        email_key = (self.config.email.strip().lower() or "default")

        if not self.config.force_login:
            if self.config.email:
                entry = data.get("users", {}).get(email_key, {})
                cookie = entry.get("cookie")
                if cookie:
                    apply_cookie_string(self.session, cookie)
                    if self._is_authenticated():
                        self._emit(f"[INFO] سشن ذخیره‌شده برای {email_key} بارگذاری شد")
                        return
                    self.session.cookies.clear()
            else:
                last_used = data.get("lastUsed")
                if last_used:
                    cookie = data.get("users", {}).get(last_used, {}).get("cookie")
                    if cookie:
                        apply_cookie_string(self.session, cookie)
                        if self._is_authenticated():
                            self._emit(f"[INFO] سشن قبلی ({last_used}) بارگذاری شد")
                            return
                        self.session.cookies.clear()

        if self.config.email and self.config.password:
            self._login(self.config.email, self.config.password)
            cookie = cookie_string_from_session(self.session)
            if cookie:
                self._write_session_file(email_key, cookie, data)
                self._emit("[INFO] سشن جدید ذخیره شد")
            return

        if not self._is_authenticated():
            raise RuntimeError("سشن معتبر پیدا نشد. ایمیل/پسورد را وارد کنید")

    def _download_file(self, url: str, output_path: Path, referer: str, sample_bytes: int = 0) -> str:
        self._check_stop()
        output_path.parent.mkdir(parents=True, exist_ok=True)
        if output_path.exists() and output_path.stat().st_size > 0:
            return "exists"

        headers = {"Referer": safe_uri(referer), "Accept": "*/*"}
        if sample_bytes > 0:
            headers["Range"] = f"bytes=0-{sample_bytes - 1}"

        with self.session.get(safe_uri(url), headers=headers, stream=True, timeout=60) as r:
            r.raise_for_status()
            content_len = int(r.headers.get("content-length") or 0)
            total_expected = sample_bytes if sample_bytes > 0 else content_len
            written = 0
            last_bucket = -1
            with output_path.open("wb") as f:
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    self._check_stop()
                    if not chunk:
                        continue
                    if sample_bytes > 0:
                        remain = sample_bytes - written
                        if remain <= 0:
                            break
                        if len(chunk) > remain:
                            chunk = chunk[:remain]
                    f.write(chunk)
                    written += len(chunk)
                    if total_expected > 0:
                        ratio = min(1.0, written / total_expected)
                        bucket = int(ratio * 20)
                        if bucket != last_bucket:
                            last_bucket = bucket
                            self._emit(
                                f"[PROGRESS] {output_path.name} [{text_progress_bar(ratio)}] {int(ratio*100)}% ({format_bytes(written)}/{format_bytes(total_expected)})"
                            )
                    if sample_bytes > 0 and written >= sample_bytes:
                        break

            if total_expected == 0:
                self._emit(f"[PROGRESS] {output_path.name} {format_bytes(written)} downloaded")
            else:
                self._emit(
                    f"[PROGRESS] {output_path.name} [{text_progress_bar(1.0)}] 100% ({format_bytes(written)}/{format_bytes(total_expected)})"
                )

        if output_path.exists() and output_path.stat().st_size == 0:
            output_path.unlink(missing_ok=True)
            raise RuntimeError(f"فایل خالی دانلود شد: {output_path.name}")
        return "downloaded"

    def _run_single_course(self, course_url: str) -> tuple[int, int, int, int]:
        self._check_stop()
        url = course_url.strip()
        if not url.endswith("/"):
            url += "/"

        slug = extract_course_slug(url)
        display_slug = unquote(slug)
        root_dir = self.config.save_dir / "download" / sanitize_name(display_slug)
        root_dir.mkdir(parents=True, exist_ok=True)

        self._emit(f"[INFO] Course slug: {display_slug}")
        self._emit(f"[INFO] Output folder: {root_dir}")

        api_url = f"{ORIGIN}/api/v1/courses/{slug}/chapters/"
        r = self.session.get(safe_uri(api_url), timeout=30)
        r.raise_for_status()
        chapters = (r.json() or {}).get("chapters") or []
        if not chapters:
            raise RuntimeError("هیچ فصلی پیدا نشد. لینک یا دسترسی را بررسی کنید")

        total_units = 0
        downloaded = 0
        skipped = 0
        failed = 0

        for chapter_index, chapter in enumerate(chapters, start=1):
            self._check_stop()
            chapter_name = sanitize_name(chapter.get("title") or chapter.get("slug") or "chapter")
            chapter_dir = root_dir / f"{chapter_index:02d} - {chapter_name}"
            units = chapter.get("unit_set") or []
            self._emit(f"[INFO] Chapter {chapter_index}/{len(chapters)}: {chapter_name}")

            for unit_index, unit in enumerate(units, start=1):
                self._check_stop()
                if not unit.get("status") or unit.get("type") != "lecture":
                    continue
                total_units += 1

                title = sanitize_name(unit.get("title") or unit.get("slug") or "lecture")
                base_name = f"{unit_index:02d} - {title}.mp4"
                final_name = base_name.replace(".mp4", ".sample.mp4") if self.config.sample_bytes > 0 else base_name
                output_path = chapter_dir / final_name

                if unit.get("locked"):
                    self._emit(f"[SKIP] Locked: {final_name}")
                    skipped += 1
                    continue

                chapter_slug = chapter.get("slug")
                chapter_id = chapter.get("id")
                unit_slug = unit.get("slug")
                lecture_url = f"{ORIGIN}/course/{slug}/{chapter_slug}-ch{chapter_id}/{unit_slug}/"

                try:
                    html = self.session.get(safe_uri(lecture_url), timeout=30).text
                    candidates = extract_video_sources(html)
                    self._debug(f"Video candidates for '{final_name}': {len(candidates)}")
                    src = pick_best_source(candidates)
                    if not src:
                        if self.config.verbose:
                            dbg_dir = self.config.save_dir / "debug_html"
                            dbg_dir.mkdir(parents=True, exist_ok=True)
                            dbg_file = dbg_dir / f"{chapter_index:02d}_{unit_index:02d}.html"
                            dbg_file.write_text(html, encoding="utf-8")
                            self._debug(f"Saved debug html: {dbg_file}")
                        self._emit(f"[SKIP] Video source not found: {final_name}")
                        skipped += 1
                        continue

                    self._emit(f"[DOWN] {final_name}")
                    state = self._download_file(src, output_path, lecture_url, self.config.sample_bytes)
                    if state == "exists":
                        skipped += 1
                        self._emit(f"[SKIP] Exists: {final_name}")
                    else:
                        downloaded += 1
                        self._emit(f"[OK] Downloaded: {final_name}")

                    video_base = final_name.replace(".sample.mp4", "").replace(".mp4", "")
                    for sub_url in extract_track_links(html):
                        self._check_stop()
                        full_sub = urljoin(ORIGIN, sub_url)
                        suffix = Path(urlparse(full_sub).path).suffix or ".vtt"
                        sub_path = chapter_dir / f"{video_base}{suffix}"
                        try:
                            s_state = self._download_file(full_sub, sub_path, lecture_url, 0)
                            if s_state == "downloaded":
                                self._emit(f"[SUB] {sub_path.name}")
                        except Exception as e:
                            self._emit(f"[WARN] Subtitle failed: {e}")

                    for att_url in extract_attachment_links(html):
                        self._check_stop()
                        full_att = urljoin(ORIGIN, att_url)
                        raw_name = Path(urlparse(full_att).path).name or "attachment.bin"
                        att_name = f"{video_base} - {sanitize_name(raw_name)}"
                        att_path = chapter_dir / att_name
                        try:
                            a_state = self._download_file(full_att, att_path, lecture_url, 0)
                            if a_state == "downloaded":
                                self._emit(f"[ATTACH] {att_name}")
                        except Exception as e:
                            self._emit(f"[WARN] Attachment failed: {e}")

                except InterruptedError:
                    raise
                except Exception as e:
                    failed += 1
                    self._emit(f"[FAIL] {final_name}: {e}")
                    self._debug(traceback.format_exc())

        self._emit("----------------------------------------")
        self._emit(f"[STAT] Total lectures: {total_units}")
        self._emit(f"[STAT] Downloaded: {downloaded}")
        self._emit(f"[STAT] Skipped: {skipped}")
        self._emit(f"[STAT] Failed: {failed}")
        return total_units, downloaded, skipped, failed

    def _run_download(self) -> None:
        self._wait_for_schedule_start()
        self._prepare_session()

        all_total = 0
        all_downloaded = 0
        all_skipped = 0
        all_failed = 0

        for idx, course_url in enumerate(self.config.course_urls, start=1):
            self._check_stop()
            self._emit(f"========== Course {idx}/{len(self.config.course_urls)} ==========")
            self._emit(f"[INFO] URL: {course_url}")
            t, d, s, f = self._run_single_course(course_url)
            all_total += t
            all_downloaded += d
            all_skipped += s
            all_failed += f

        self._emit("========================================")
        self._emit(f"[FINAL] Total lectures: {all_total}")
        self._emit(f"[FINAL] Downloaded: {all_downloaded}")
        self._emit(f"[FINAL] Skipped: {all_skipped}")
        self._emit(f"[FINAL] Failed: {all_failed}")

    def run(self) -> None:
        try:
            self._run_download()
            self.done.emit(True, "دانلود تکمیل شد")
        except InterruptedError as e:
            self.done.emit(False, str(e) or "دانلود متوقف شد")
        except Exception as e:
            self.done.emit(False, f"خطا: {e}")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Maktabkhooneh Downloader - Python Only")
        self.resize(980, 760)

        self.worker: DownloaderThread | None = None
        self.project_dir = Path(__file__).resolve().parent
        self._last_dynamic_tag: str | None = None
        self._build_ui()
        self._apply_theme()

    def _build_ui(self) -> None:
        root = QWidget()
        root.setObjectName("root")
        self.setCentralWidget(root)
        main_layout = QVBoxLayout(root)
        main_layout.setContentsMargins(18, 16, 18, 16)
        main_layout.setSpacing(12)

        config_box = QGroupBox("تنظیمات دانلود")
        config_box.setObjectName("panel")
        form = QFormLayout(config_box)
        form.setHorizontalSpacing(14)
        form.setVerticalSpacing(10)

        self.single_course_url = QLineEdit()
        self.single_course_url.setPlaceholderText("https://maktabkhooneh.org/course/<slug>/")
        form.addRow("لینک دوره:", self.single_course_url)

        self.bulk_mode = QCheckBox("دانلود دست‌جمعی")
        self.bulk_mode.toggled.connect(self._toggle_bulk_mode)
        form.addRow("حالت دانلود:", self.bulk_mode)

        self.bulk_links_widget = QWidget()
        bulk_layout = QVBoxLayout(self.bulk_links_widget)
        bulk_layout.setContentsMargins(0, 0, 0, 0)
        bulk_layout.setSpacing(6)

        bulk_actions = QHBoxLayout()
        self.add_link_btn = QPushButton("+ افزودن لینک")
        self.add_link_btn.clicked.connect(lambda: self._add_bulk_link_row())
        bulk_actions.addWidget(self.add_link_btn)
        bulk_actions.addStretch()
        bulk_layout.addLayout(bulk_actions)

        self.bulk_rows_container = QWidget()
        self.bulk_rows_layout = QVBoxLayout(self.bulk_rows_container)
        self.bulk_rows_layout.setContentsMargins(0, 0, 0, 0)
        self.bulk_rows_layout.setSpacing(6)
        self.bulk_link_inputs: list[QLineEdit] = []
        self._add_bulk_link_row()

        bulk_layout.addWidget(self.bulk_rows_container)
        self.bulk_links_widget.setVisible(False)
        form.addRow("لیست لینک‌ها:", self.bulk_links_widget)

        self.email = QLineEdit()
        self.email.setPlaceholderText("اختیاری: ایمیل یا موبایل")
        form.addRow("ایمیل یا موبایل:", self.email)

        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.password.setPlaceholderText("اختیاری: برای ساخت/تازه سازی سشن")
        form.addRow("پسورد:", self.password)

        self.sample_bytes = QSpinBox()
        self.sample_bytes.setRange(0, 2_147_483_647)
        self.sample_bytes.setSingleStep(65536)
        self.sample_bytes.setValue(0)
        self.sample_bytes.setToolTip("0 یعنی دانلود کامل")
        form.addRow("Sample bytes:", self.sample_bytes)

        self.verbose = QCheckBox("Verbose log")
        self.force_login = QCheckBox("Force login")
        self.shutdown_after = QCheckBox("خاموش کردن سیستم بعد از اتمام")
        self.dark_mode = QCheckBox("Dark mode")
        self.dark_mode.toggled.connect(self._apply_theme)
        row_opts = QHBoxLayout()
        row_opts.addWidget(self.verbose)
        row_opts.addWidget(self.force_login)
        row_opts.addWidget(self.shutdown_after)
        row_opts.addWidget(self.dark_mode)
        row_opts.addStretch()
        form.addRow("گزینه‌ها:", row_opts)

        self.use_start_time = QCheckBox("شروع زمان‌بندی‌شده")
        self.use_start_time.toggled.connect(self._toggle_schedule_controls)
        self.start_date_edit = QDateEdit(QDate.currentDate())
        self.start_date_edit.setCalendarPopup(True)
        self.start_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.start_time_edit = QTimeEdit(QTime.currentTime())
        self.start_time_edit.setDisplayFormat("HH:mm")
        start_row = QHBoxLayout()
        start_row.addWidget(self.use_start_time)
        start_row.addWidget(self.start_date_edit)
        start_row.addWidget(self.start_time_edit)
        form.addRow("زمان شروع:", start_row)

        self.use_end_time = QCheckBox("پایان زمان‌بندی‌شده")
        self.use_end_time.toggled.connect(self._toggle_schedule_controls)
        self.end_date_edit = QDateEdit(QDate.currentDate())
        self.end_date_edit.setCalendarPopup(True)
        self.end_date_edit.setDisplayFormat("yyyy-MM-dd")
        self.end_time_edit = QTimeEdit(QTime.currentTime().addSecs(3600))
        self.end_time_edit.setDisplayFormat("HH:mm")
        end_row = QHBoxLayout()
        end_row.addWidget(self.use_end_time)
        end_row.addWidget(self.end_date_edit)
        end_row.addWidget(self.end_time_edit)
        form.addRow("زمان پایان:", end_row)

        save_row = QHBoxLayout()
        self.save_dir = QLineEdit(str(self.project_dir))
        self.save_browse = QPushButton("انتخاب")
        self.save_browse.clicked.connect(self._pick_save_dir)
        save_row.addWidget(self.save_dir)
        save_row.addWidget(self.save_browse)
        form.addRow("محل ذخیره:", save_row)

        main_layout.addWidget(config_box)

        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        self.start_btn = QPushButton("شروع دانلود")
        self.start_btn.setObjectName("startBtn")
        self.stop_btn = QPushButton("توقف")
        self.stop_btn.setObjectName("stopBtn")
        self.stop_btn.setEnabled(False)
        self.clear_btn = QPushButton("پاک کردن لاگ")
        self.clear_btn.setObjectName("neutralBtn")

        self.start_btn.clicked.connect(self.start_download)
        self.stop_btn.clicked.connect(self.stop_download)
        self.clear_btn.clicked.connect(self.log_box_clear)

        btn_row.addWidget(self.start_btn)
        btn_row.addWidget(self.stop_btn)
        btn_row.addWidget(self.clear_btn)
        btn_row.addStretch()

        self.status_label = QLabel("وضعیت: آماده")
        self.status_label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        btn_row.addWidget(self.status_label)
        main_layout.addLayout(btn_row)

        self.log_box = QPlainTextEdit()
        self.log_box.setObjectName("logBox")
        self.log_box.setReadOnly(True)
        self.log_box.setPlaceholderText("لاگ دانلود اینجا نمایش داده می‌شود...")
        main_layout.addWidget(self.log_box)

        github_label = QLabel('<a href="https://github.com/Mtgama">GitHub: @Mtgama</a>')
        github_label.setOpenExternalLinks(True)
        github_label.setTextFormat(Qt.RichText)
        github_label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        github_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        main_layout.addWidget(github_label)
        self._toggle_schedule_controls()

    def _apply_theme(self, _checked: bool | None = None) -> None:
        if hasattr(self, "dark_mode") and self.dark_mode.isChecked():
            self._apply_dark_theme()
        else:
            self._apply_light_theme()

    def _apply_light_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget#root {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #edf4ff, stop:0.5 #f5f9ff, stop:1 #eefbf4);
                color: #1d2939;
                font-family: "Vazirmatn", "Segoe UI", "Noto Sans Arabic", sans-serif;
                font-size: 13px;
            }

            QGroupBox#panel {
                background: #ffffff;
                border: 1px solid #d7e3f4;
                border-radius: 14px;
                margin-top: 14px;
                padding: 14px 12px 12px 12px;
                font-weight: 600;
            }

            QGroupBox#panel::title {
                subcontrol-origin: margin;
                left: 12px;
                top: -10px;
                background: #2f6fd4;
                color: #ffffff;
                border-radius: 8px;
                padding: 4px 10px;
            }

            QLabel {
                color: #334155;
                font-weight: 500;
            }

            QLineEdit, QPlainTextEdit, QSpinBox, QDateEdit, QTimeEdit {
                background: #ffffff;
                border: 1px solid #cad8ef;
                border-radius: 10px;
                padding: 8px 10px;
                selection-background-color: #2f6fd4;
                selection-color: #ffffff;
            }

            QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDateEdit:focus, QTimeEdit:focus {
                border: 1px solid #2f6fd4;
            }

            QPushButton {
                background: #ecf2ff;
                border: 1px solid #cedcf4;
                border-radius: 10px;
                padding: 8px 14px;
                font-weight: 600;
                color: #234;
            }

            QPushButton:hover {
                background: #e2ebff;
            }

            QPushButton:disabled {
                background: #f1f5fb;
                color: #9aa7b7;
                border-color: #dfe7f2;
            }

            QPushButton#startBtn {
                background: #1f9d67;
                color: #ffffff;
                border: 1px solid #1a8457;
            }

            QPushButton#startBtn:hover {
                background: #188a5a;
            }

            QPushButton#stopBtn {
                background: #df3e4f;
                color: #ffffff;
                border: 1px solid #c62d3f;
            }

            QPushButton#stopBtn:hover {
                background: #cb3244;
            }

            QCheckBox {
                spacing: 8px;
                color: #2b3d52;
            }

            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 5px;
                border: 1px solid #93a9cc;
                background: #ffffff;
            }

            QCheckBox::indicator:checked {
                background: #2f6fd4;
                border: 1px solid #2f6fd4;
            }

            QPlainTextEdit#logBox {
                background: #0f172a;
                color: #dbeafe;
                border: 1px solid #1e293b;
                border-radius: 12px;
                padding: 10px;
                font-family: "JetBrains Mono", "Consolas", monospace;
                font-size: 12px;
            }

            QLabel[href] {
                color: #2f6fd4;
            }
            """
        )

    def _apply_dark_theme(self) -> None:
        self.setStyleSheet(
            """
            QWidget#root {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #0b1220, stop:0.5 #111827, stop:1 #0b1f1a);
                color: #e5edf8;
                font-family: "Vazirmatn", "Segoe UI", "Noto Sans Arabic", sans-serif;
                font-size: 13px;
            }

            QGroupBox#panel {
                background: #111827;
                border: 1px solid #334155;
                border-radius: 14px;
                margin-top: 14px;
                padding: 14px 12px 12px 12px;
                font-weight: 600;
            }

            QGroupBox#panel::title {
                subcontrol-origin: margin;
                left: 12px;
                top: -10px;
                background: #1d4ed8;
                color: #ffffff;
                border-radius: 8px;
                padding: 4px 10px;
            }

            QLabel {
                color: #dbe7fb;
                font-weight: 500;
            }

            QLineEdit, QPlainTextEdit, QSpinBox, QDateEdit, QTimeEdit {
                background: #0f172a;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 8px 10px;
                selection-background-color: #2563eb;
                selection-color: #ffffff;
            }

            QLineEdit:focus, QPlainTextEdit:focus, QSpinBox:focus, QDateEdit:focus, QTimeEdit:focus {
                border: 1px solid #60a5fa;
            }

            QPushButton {
                background: #1e293b;
                border: 1px solid #334155;
                border-radius: 10px;
                padding: 8px 14px;
                font-weight: 600;
                color: #e2e8f0;
            }

            QPushButton:hover {
                background: #26354a;
            }

            QPushButton:disabled {
                background: #111827;
                color: #64748b;
                border-color: #1f2937;
            }

            QPushButton#startBtn {
                background: #15803d;
                color: #ffffff;
                border: 1px solid #166534;
            }

            QPushButton#startBtn:hover {
                background: #166534;
            }

            QPushButton#stopBtn {
                background: #be123c;
                color: #ffffff;
                border: 1px solid #9f1239;
            }

            QPushButton#stopBtn:hover {
                background: #9f1239;
            }

            QCheckBox {
                spacing: 8px;
                color: #dbe7fb;
            }

            QCheckBox::indicator {
                width: 16px;
                height: 16px;
                border-radius: 5px;
                border: 1px solid #64748b;
                background: #0f172a;
            }

            QCheckBox::indicator:checked {
                background: #3b82f6;
                border: 1px solid #3b82f6;
            }

            QPlainTextEdit#logBox {
                background: #020617;
                color: #bfdbfe;
                border: 1px solid #1e293b;
                border-radius: 12px;
                padding: 10px;
                font-family: "JetBrains Mono", "Consolas", monospace;
                font-size: 12px;
            }

            QLabel[href] {
                color: #60a5fa;
            }
            """
        )

    def _add_bulk_link_row(self, text: str = "") -> None:
        if not isinstance(text, str):
            text = ""
        row_widget = QWidget()
        row_layout = QHBoxLayout(row_widget)
        row_layout.setContentsMargins(0, 0, 0, 0)
        row_layout.setSpacing(6)

        line = QLineEdit(text)
        line.setPlaceholderText("https://maktabkhooneh.org/course/<slug>/")
        remove_btn = QPushButton("حذف")
        remove_btn.setFixedWidth(70)
        remove_btn.clicked.connect(lambda: self._remove_bulk_link_row(row_widget, line))

        row_layout.addWidget(line)
        row_layout.addWidget(remove_btn)
        self.bulk_rows_layout.addWidget(row_widget)
        self.bulk_link_inputs.append(line)

    def _remove_bulk_link_row(self, row_widget: QWidget, line: QLineEdit) -> None:
        if len(self.bulk_link_inputs) <= 1:
            line.clear()
            return
        self.bulk_link_inputs = [x for x in self.bulk_link_inputs if x is not line]
        row_widget.setParent(None)
        row_widget.deleteLater()

    def _toggle_bulk_mode(self) -> None:
        self.bulk_links_widget.setVisible(self.bulk_mode.isChecked())
        self.single_course_url.setEnabled(not self.bulk_mode.isChecked())

    def _toggle_schedule_controls(self) -> None:
        start_enabled = self.use_start_time.isChecked()
        end_enabled = self.use_end_time.isChecked()
        self.start_date_edit.setEnabled(start_enabled)
        self.start_time_edit.setEnabled(start_enabled)
        self.end_date_edit.setEnabled(end_enabled)
        self.end_time_edit.setEnabled(end_enabled)

    def _pick_save_dir(self) -> None:
        folder = QFileDialog.getExistingDirectory(
            self,
            "انتخاب پوشه ذخیره",
            self.save_dir.text().strip() or str(self.project_dir),
        )
        if folder:
            self.save_dir.setText(folder)

    def _append_log(self, text: str) -> None:
        text = (text or "").strip("\n")
        if not text:
            return

        dynamic_tag: str | None = None
        if text.startswith("[PROGRESS] "):
            dynamic_tag = "progress"
        elif text.startswith("[INFO] در انتظار شروع زمان‌بندی‌شده..."):
            dynamic_tag = "countdown"

        cursor = self.log_box.textCursor()
        cursor.movePosition(QTextCursor.End)
        has_text = bool(self.log_box.toPlainText())

        if dynamic_tag and self._last_dynamic_tag == dynamic_tag and has_text:
            cursor.movePosition(QTextCursor.StartOfLine, QTextCursor.KeepAnchor)
            cursor.removeSelectedText()
            cursor.insertText(text)
        else:
            if has_text:
                cursor.insertBlock()
            cursor.insertText(text)

        self._last_dynamic_tag = dynamic_tag
        self.log_box.verticalScrollBar().setValue(self.log_box.verticalScrollBar().maximum())

    def log_box_clear(self) -> None:
        self.log_box.clear()
        self._last_dynamic_tag = None

    def _set_running_ui(self, running: bool) -> None:
        self.start_btn.setEnabled(not running)
        self.stop_btn.setEnabled(running)
        self.save_browse.setEnabled(not running)
        self.add_link_btn.setEnabled(not running)
        self.bulk_mode.setEnabled(not running)
        self.single_course_url.setEnabled((not running) and (not self.bulk_mode.isChecked()))
        for line in self.bulk_link_inputs:
            line.setEnabled(not running)
        self.use_start_time.setEnabled(not running)
        self.use_end_time.setEnabled(not running)
        if not running:
            self._toggle_schedule_controls()

    def _collect_urls(self) -> list[str]:
        if self.bulk_mode.isChecked():
            urls = [line.text().strip() for line in self.bulk_link_inputs if line.text().strip()]
        else:
            one = self.single_course_url.text().strip()
            urls = [one] if one else []
        unique: list[str] = []
        seen: set[str] = set()
        for u in urls:
            if u not in seen:
                seen.add(u)
                unique.append(u)
        return unique

    def _schedule_timestamps(self) -> tuple[float | None, float | None]:
        start_ts = None
        end_ts = None
        if self.use_start_time.isChecked():
            start_dt = datetime.combine(self.start_date_edit.date().toPyDate(), self.start_time_edit.time().toPyTime())
            start_ts = start_dt.timestamp()
        if self.use_end_time.isChecked():
            end_dt = datetime.combine(self.end_date_edit.date().toPyDate(), self.end_time_edit.time().toPyTime())
            end_ts = end_dt.timestamp()
        return start_ts, end_ts

    def _validate(self) -> tuple[bool, str]:
        urls = self._collect_urls()
        if not urls:
            return False, "حداقل یک لینک دوره وارد کن"
        for u in urls:
            if "maktabkhooneh.org/course/" not in u:
                return False, f"لینک نامعتبر: {u}"

        save = Path(self.save_dir.text().strip() or ".")
        if not save.exists():
            return False, f"پوشه ذخیره پیدا نشد: {save}"

        start_ts, end_ts = self._schedule_timestamps()

        if start_ts and end_ts and start_ts >= end_ts:
            return False, "زمان شروع باید قبل از زمان پایان باشد"
        return True, ""

    def _request_shutdown_confirm(self) -> bool:
        if not self.shutdown_after.isChecked():
            return True
        answer = QMessageBox.question(
            self,
            "تایید خاموش کردن",
            "پس از اتمام دانلود، سیستم خاموش شود؟",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        return answer == QMessageBox.Yes

    def start_download(self) -> None:
        ok, msg = self._validate()
        if not ok:
            QMessageBox.warning(self, "خطا", msg)
            return

        if not self._request_shutdown_confirm():
            return

        if self.worker is not None:
            QMessageBox.information(self, "در حال اجرا", "یک دانلود در حال اجراست")
            return

        start_ts, end_ts = self._schedule_timestamps()
        urls = self._collect_urls()

        cfg = DownloadConfig(
            course_urls=urls,
            save_dir=Path(self.save_dir.text().strip() or "."),
            email=self.email.text().strip(),
            password=self.password.text().strip(),
            sample_bytes=self.sample_bytes.value(),
            verbose=self.verbose.isChecked(),
            force_login=self.force_login.isChecked(),
            start_ts=start_ts,
            end_ts=end_ts,
        )

        self.log_box_clear()
        self._append_log(f"[INFO] Starting python downloader for {len(urls)} course(s)...")
        if start_ts is not None:
            self._append_log(f"[INFO] Start at: {datetime.fromtimestamp(start_ts):%Y-%m-%d %H:%M:%S}")
        if end_ts is not None:
            self._append_log(f"[INFO] End at: {datetime.fromtimestamp(end_ts):%Y-%m-%d %H:%M:%S}")

        self.worker = DownloaderThread(cfg)
        self.worker.log.connect(self._append_log)
        self.worker.done.connect(self._on_done)

        self._set_running_ui(True)
        self.status_label.setText("وضعیت: در حال دانلود...")
        self.worker.start()

    def stop_download(self) -> None:
        if self.worker is None:
            return
        self._append_log("[INFO] درخواست توقف ارسال شد...")
        self.status_label.setText("وضعیت: در حال توقف...")
        self.worker.stop()

    def _shutdown_system(self) -> None:
        try:
            os_name = platform.system().lower()
            if "windows" in os_name:
                subprocess.Popen(["shutdown", "/s", "/t", "0"])
            elif "darwin" in os_name:
                subprocess.Popen(["shutdown", "-h", "now"])
            else:
                subprocess.Popen(["shutdown", "-h", "now"])
            self._append_log("[INFO] دستور خاموش کردن سیستم ارسال شد")
        except Exception as e:
            self._append_log(f"[WARN] ارسال دستور خاموشی ناموفق بود: {e}")

    def _on_done(self, success: bool, message: str) -> None:
        self._append_log(message)

        if success:
            self.status_label.setText("وضعیت: تکمیل شد")
            if self.shutdown_after.isChecked():
                self._shutdown_system()
        else:
            if "متوقف" in message or "بازه زمانی" in message:
                self.status_label.setText("وضعیت: متوقف شد")
            else:
                self.status_label.setText("وضعیت: خطا")

        if self.worker is not None:
            self.worker.wait(1000)
            self.worker.deleteLater()
            self.worker = None
        self._set_running_ui(False)


def main() -> int:
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    return app.exec_()


if __name__ == "__main__":
    raise SystemExit(main())
