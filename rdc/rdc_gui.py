#!/usr/bin/env python3
"""rdc_gui.py - a simple desktop window for rdc4.py (research-data-compress v3.1.6).

Put this file in the same folder as rdc4.py and start it with the Python that has
rdc4's requirements installed, for example on Ubuntu:

    ~/rdc/research-data-compress-v3.1.6/.venv/bin/python ~/rdc/research-data-compress-v3.1.6/rdc_gui.py

It only uses the Python standard library (Tkinter). Drag and drop of files and folders
works when the optional package tkinterdnd2 is installed in the same Python
(.venv/bin/pip install tkinterdnd2); without it the window works the same, minus dragging. It does not change rdc4.py; every
button runs rdc4.py as a separate process, exactly like typing the command yourself.
The password is passed through the RDC_PASSWORD environment variable, never on the
command line, and is never written to disk.
"""

import json
import os
import queue
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

# Drag and drop needs the optional tkinterdnd2 package (pip install tkinterdnd2).
# Without it, everything else still works; you just use the Choose buttons.
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    _BaseTk = TkinterDnD.Tk
except Exception:  # not installed, or its native part could not load
    DND_FILES = None
    _BaseTk = tk.Tk

APP_TITLE = 'RDC Archiver'
SETTINGS_FILE = os.path.join(os.path.expanduser('~'), '.rdc_gui.json')
HERE = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------- helpers

def human_size(n):
    try:
        n = float(n)
    except (TypeError, ValueError):
        return str(n)
    for unit in ('bytes', 'KB', 'MB', 'GB', 'TB'):
        if abs(n) < 1024 or unit == 'TB':
            return ('%d %s' % (n, unit)) if unit == 'bytes' else ('%.1f %s' % (n, unit))
        n /= 1024.0


def load_settings():
    try:
        with open(SETTINGS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_settings(data):
    # Write to a temporary file first, then swap it in, so a crash never leaves a half-written file.
    tmp = SETTINGS_FILE + '.tmp'
    try:
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, SETTINGS_FILE)
    except OSError:
        try:
            os.remove(tmp)
        except OSError:
            pass


def path_inside(child, parent):
    """True if child is parent or inside it (case-insensitive on Windows)."""
    c = os.path.normcase(os.path.abspath(child))
    p = os.path.normcase(os.path.abspath(parent)).rstrip('\\/')
    return c == p or c.startswith(p + os.sep)


def file_uri_to_path(uri):
    """file:///home/x/a b -> /home/x/a b ; file://server/share/x -> \\\\server\\share\\x on Windows."""
    from urllib.parse import unquote, urlparse
    u = urlparse(uri)
    path = unquote(u.path)
    host = u.netloc
    if host and host.lower() != 'localhost':
        if sys.platform == 'win32':
            return '\\\\' + host + path.replace('/', '\\')
        return '//' + host + path
    if sys.platform == 'win32' and path.startswith('/') and len(path) > 2 and path[2] == ':':
        path = path[1:]
    return path


def find_rdc4(settings):
    candidates = [
        settings.get('rdc4_path', ''),
        os.path.join(HERE, 'rdc4.py'),
        os.path.join(os.getcwd(), 'rdc4.py'),
        os.path.join(os.path.expanduser('~'), 'rdc', 'research-data-compress-v3.1.6', 'rdc4.py'),
    ]
    for c in candidates:
        if c and os.path.isfile(c):
            return os.path.abspath(c)
    return ''


MAX_THREADS = 32           # rdc4's own limit on --threads
# Repair data choices: (label, extra pack arguments). Numbers, not preset names, so an older rdc4.py also works.
REPAIR_CHOICES = [
    ('Standard: fixes the most damage (about 20% bigger, recommended)', []),
    ('Light: fixes about half as much damage (about 10% bigger)', ['--parity', '20,2']),
    ('None: smallest, but damage cannot be fixed', ['--no-parity']),
]
LOG_LINE_LIMIT = 5000      # the log box keeps at most this many lines (oldest are dropped)
EVENTS_PER_TICK = 200      # at most this many queued messages are handled per screen update

STAGE_NAMES = {
    'pack': 'Reading and compressing',
    'parity': 'Adding repair data',
    'unpack': 'Extracting',
    'verify': 'Checking',
}


def parse_json_lines(text):
    """Return the last result/error JSON object printed in text (progress lines are skipped), or None."""
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith('{'):
            try:
                obj = json.loads(line)
            except ValueError:
                continue
            if isinstance(obj, dict) and obj.get('event') == 'progress':
                continue
            return obj
    return None


def parse_progress_line(line):
    """{"event": "progress", "stage": ..., "done": N, "total": T} -> dict, anything else -> None."""
    line = line.strip()
    if not (line.startswith('{"event"') and '"progress"' in line):
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if obj.get('event') != 'progress':
        return None
    return obj


def probe_capabilities(python, rdc4):
    """Ask rdc4.py which optional GUI add-on options it has (an unchanged v3.1.6 has neither)."""
    caps = {'progress': False, 'password_stdin': False}
    try:
        kw = {}
        if sys.platform == 'win32':
            kw['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        rdc4 = os.path.abspath(rdc4)
        out = subprocess.run([python, rdc4, 'pack', '--help'], capture_output=True, text=True,
                             timeout=60, cwd=os.path.dirname(rdc4), **kw).stdout
        caps['progress'] = '--progress' in out
        caps['password_stdin'] = '--password-stdin' in out
    except (OSError, subprocess.SubprocessError):
        pass
    return caps


def friendly_error(err, raw_stderr):
    """Turn an rdc4 error into a sentence a person can act on."""
    if err is None:
        lines = [l for l in raw_stderr.strip().splitlines() if l.strip()]
        last = lines[-1] if lines else 'rdc4 stopped without a message.'
        if 'FileNotFoundError' in last:
            return 'A file or folder could not be found. Check the paths above.\n(' + last + ')'
        if 'PermissionError' in last:
            return 'Permission denied. Pick a folder you are allowed to write to.\n(' + last + ')'
        if 'ModuleNotFoundError' in last or 'No module named' in last:
            return ('rdc4 is missing a Python package. Start this window with the Python inside the '
                    '.venv folder (see the instructions).\n(' + last + ')')
        return last
    kind = err.get('error', 'Error')
    msg = err.get('message', '')
    low = msg.lower()
    if 'password required' in low:
        return 'This archive is encrypted. Type its password in the Password box at the top and try again.'
    if 'wrong password' in low:
        return ('The password is wrong, or the archive is damaged at its start. '
                'Check the password (it is case-sensitive) and try again.')
    if 'bad magic' in low:
        return 'That file is not an RDC archive. Pick a .rdc4 (or .rdc3) archive file.'
    if 'destination exists' in low or kind == 'FileExistsError':
        return ('Something with that name already exists, and rdc4 never overwrites anything. '
                'Pick an empty folder or a new file name.\n(' + msg + ')')
    if kind == 'PublicationError':
        return ('The archive could not be saved safely (stage: %s). Check free disk space and try again.\n(%s)'
                % (err.get('stage'), msg))
    return '%s: %s' % (kind, msg)


# ---------------------------------------------------------------- window

ARCHIVE_EXTS = ('.rdc4', '.rdc3', '.rdc')


def is_archive_name(path):
    return os.path.isfile(path) and path.lower().endswith(ARCHIVE_EXTS)


class App(_BaseTk):
    def __init__(self):
        self.dnd = False
        try:
            super().__init__()
            self.dnd = DND_FILES is not None
        except Exception:
            # tkinterdnd2 is installed but its native library would not load: run without it.
            if not getattr(self, 'tk', None):
                tk.Tk.__init__(self)
        self.drop_fields = []  # (entry widget, kind, tk variable)
        self.up_only_arc = ''      # the archive the "only these files" pick belongs to
        self._rp_auto = ''         # last auto-suggested repair output name
        self.vf_queue = []         # archives still waiting to be verified
        self.vf_results = []       # (archive, outcome) for the current verify batch
        self.ls_result = None      # last "What's inside" listing, for filtering
        self.ls_sort = ('name', False)
        self.caps = {'progress': False, 'password_stdin': False}
        self.caps_for = None       # which rdc4.py the capabilities belong to
        self.prog_stage = None     # current progress stage and when it started (for speed)
        self.prog_t0 = 0.0
        self.log_dropped = 0
        self.latest_progress = None
        self.prog_detail = ''
        self.title(APP_TITLE)
        self.minsize(760, 600)
        self.settings = load_settings()
        self.rdc4 = find_rdc4(self.settings)
        self.proc = None
        self.events = queue.Queue()
        self.started = 0.0
        self.on_done = None
        self.cancelled = False

        style = ttk.Style(self)
        if sys.platform.startswith('linux') and 'clam' in style.theme_names():
            style.theme_use('clam')
        style.configure('Big.TButton', padding=(14, 6))
        style.configure('Good.TLabel', foreground='#1a7f37')
        style.configure('Bad.TLabel', foreground='#b42318')
        style.configure('Hint.TLabel', foreground='#666666')

        self._build_top()
        self._build_tabs()
        self._build_bottom()
        self._refresh_rdc4_label()
        self._probe_caps_async()
        self.up_arc.trace_add('write', lambda *_: self._on_up_arc_changed())
        self._setup_dnd()
        self.after(100, self._poll)
        self.protocol('WM_DELETE_WINDOW', self._on_close)

    # ---- layout -------------------------------------------------------
    def _build_top(self):
        top = ttk.Frame(self, padding=(10, 10, 10, 0))
        top.pack(fill='x')
        ttk.Label(top, text='Password:').grid(row=0, column=0, sticky='w')
        self.password = tk.StringVar()
        self.pw_entry = ttk.Entry(top, textvariable=self.password, show='•', width=28)
        self.pw_entry.grid(row=0, column=1, sticky='w', padx=(6, 6))
        self.show_pw = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text='Show', variable=self.show_pw,
                        command=lambda: self.pw_entry.configure(show='' if self.show_pw.get() else '•')
                        ).grid(row=0, column=2, sticky='w')
        ttk.Button(top, text='Clear', width=6, command=lambda: self.password.set('')).grid(
            row=0, column=4, sticky='w', padx=(4, 0))
        ttk.Label(top, text='Only needed for encrypted archives. Never saved.',
                  style='Hint.TLabel').grid(row=0, column=5, sticky='w', padx=(10, 0))
        self.rdc4_label = ttk.Label(top, style='Hint.TLabel')
        self.rdc4_label.grid(row=1, column=0, columnspan=5, sticky='w', pady=(6, 0))
        ttk.Button(top, text='Find rdc4.py…', command=self._pick_rdc4).grid(row=1, column=5, sticky='e', pady=(6, 0))
        top.columnconfigure(5, weight=1)

    def _path_row(self, parent, row, label, var, buttons, kind=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky='w', pady=4)
        entry = ttk.Entry(parent, textvariable=var)
        entry.grid(row=row, column=1, sticky='ew', padx=6, pady=4)
        if kind:
            self.drop_fields.append((entry, kind, var))
        col = 2
        for text, cmd in buttons:
            ttk.Button(parent, text=text, command=cmd).grid(row=row, column=col, sticky='w', padx=(0, 4), pady=4)
            col += 1
        parent.columnconfigure(1, weight=1)

    def _build_tabs(self):
        self.nb = ttk.Notebook(self)
        self.nb.pack(fill='x', padx=10, pady=10)
        self._build_pack_tab()
        self._build_unpack_tab()
        self._build_verify_tab()
        self._build_repair_tab()
        self._build_list_tab()

    def _build_pack_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text='  Pack (compress)  ')
        ttk.Label(f, text='Compress a folder or a single file into one archive file.',
                  style='Hint.TLabel').grid(row=0, column=0, columnspan=4, sticky='w', pady=(0, 6))
        self.pk_src = tk.StringVar()
        self.pk_out = tk.StringVar()
        self._path_row(f, 1, 'What to compress:', self.pk_src,
                       [('Folder…', self._pk_pick_folder), ('File…', self._pk_pick_file)],
                       kind='pack_src')
        self._path_row(f, 2, 'Save archive as:', self.pk_out, [('Choose…', self._pk_pick_out)],
                       kind='save_as')

        opts = ttk.Frame(f)
        opts.grid(row=3, column=0, columnspan=4, sticky='w', pady=(8, 0))
        ttk.Label(opts, text='Compression:').grid(row=0, column=0, sticky='w')
        self.pk_level = tk.StringVar(value='Smallest file (slower, level 19)')
        ttk.Combobox(opts, textvariable=self.pk_level, state='readonly', width=34,
                     values=['Smallest file (slower, level 19)', 'Faster (a bit bigger, level 9)']
                     ).grid(row=0, column=1, sticky='w', padx=6)
        ttk.Label(opts, text='CPU threads:').grid(row=0, column=2, sticky='w', padx=(16, 0))
        cores = max(1, min(MAX_THREADS, os.cpu_count() or 1))   # every core; the archive is identical either way
        self.pk_threads = tk.IntVar(value=cores)
        ttk.Spinbox(opts, from_=1, to=cores, textvariable=self.pk_threads,
                    width=5).grid(row=0, column=3, sticky='w', padx=6)

        rep = ttk.Frame(f)
        rep.grid(row=4, column=0, columnspan=4, sticky='w', pady=(8, 0))
        ttk.Label(rep, text='Repair data:').grid(row=0, column=0, sticky='w')
        self.pk_parity = tk.StringVar(value=REPAIR_CHOICES[0][0])
        ttk.Combobox(rep, textvariable=self.pk_parity, state='readonly', width=58,
                     values=[label for label, _args in REPAIR_CHOICES]).grid(row=0, column=1, sticky='w', padx=6)
        self.pk_encrypt = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text='Encrypt with the password typed at the top',
                        variable=self.pk_encrypt).grid(row=5, column=0, columnspan=4, sticky='w', pady=(4, 0))
        ttk.Button(f, text='Pack', style='Big.TButton', command=self.do_pack).grid(
            row=6, column=0, columnspan=4, sticky='e', pady=(10, 0))

    def _build_unpack_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text='  Unpack (extract)  ')
        ttk.Label(f, text='Get the files back out of an archive. Nothing that already exists is overwritten.',
                  style='Hint.TLabel').grid(row=0, column=0, columnspan=4, sticky='w', pady=(0, 6))
        self.up_arc = tk.StringVar()
        self.up_dest = tk.StringVar()
        self._path_row(f, 1, 'Archive:', self.up_arc, [('Choose…', lambda: self._pick_archive(self.up_arc))],
                       kind='archive')
        self._path_row(f, 2, 'Extract into folder:', self.up_dest,
                       [('Choose…', lambda: self._pick_dir(self.up_dest, 'Choose an empty folder to extract into'))],
                       kind='dest_dir')
        self.up_only = []
        row = ttk.Frame(f)
        row.grid(row=3, column=0, columnspan=4, sticky='w', pady=(8, 0))
        ttk.Button(row, text='Pick only some files…', command=self._up_pick_some).pack(side='left')
        self.up_only_label = ttk.Label(row, text='All files will be extracted.', style='Hint.TLabel')
        self.up_only_label.pack(side='left', padx=8)
        self.up_recover = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text='Recover mode: if some files are damaged, still extract everything that is good',
                        variable=self.up_recover).grid(row=4, column=0, columnspan=4, sticky='w', pady=(8, 0))
        ttk.Button(f, text='Unpack', style='Big.TButton', command=self.do_unpack).grid(
            row=5, column=0, columnspan=4, sticky='e', pady=(10, 0))

    def _build_verify_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text='  Verify (check)  ')
        ttk.Label(f, text='Check that every file in one or more archives can still be read back perfectly. '
                          'Nothing is extracted or changed.',
                  style='Hint.TLabel').grid(row=0, column=0, columnspan=3, sticky='w', pady=(0, 6))
        self.vf_arc = tk.StringVar()  # the archive being checked right now
        self.vf_list = tk.Listbox(f, height=5, selectmode='extended', activestyle='none')
        self.vf_list.grid(row=1, column=0, rowspan=3, sticky='nsew')
        sb = ttk.Scrollbar(f, orient='vertical', command=self.vf_list.yview)
        sb.grid(row=1, column=1, rowspan=3, sticky='ns')
        self.vf_list.configure(yscrollcommand=sb.set)
        ttk.Button(f, text='Add archives…', command=self._vf_add_dialog).grid(row=1, column=2, sticky='ew', padx=(8, 0))
        ttk.Button(f, text='Remove', command=self._vf_remove).grid(row=2, column=2, sticky='ew', padx=(8, 0), pady=4)
        ttk.Button(f, text='Clear list', command=lambda: self.vf_list.delete(0, 'end')).grid(
            row=3, column=2, sticky='new', padx=(8, 0))
        f.columnconfigure(0, weight=1)
        ttk.Label(f, text='Add several archives to check them one after another.',
                  style='Hint.TLabel').grid(row=4, column=0, sticky='w', pady=(6, 0))
        ttk.Button(f, text='Verify', style='Big.TButton', command=self.do_verify).grid(
            row=4, column=2, sticky='e', pady=(10, 0))
        self.drop_fields.append((self.vf_list, 'verify_add', None))

    def _build_repair_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text='  Repair  ')
        ttk.Label(f, text='Use the repair data inside a damaged archive to write a fixed copy. '
                          'The original is left untouched.',
                  style='Hint.TLabel').grid(row=0, column=0, columnspan=4, sticky='w', pady=(0, 6))
        self.rp_arc = tk.StringVar()
        self.rp_out = tk.StringVar()
        self._path_row(f, 1, 'Damaged archive:', self.rp_arc,
                       [('Choose…', lambda: self._pick_archive(self.rp_arc, suggest_repair=True))],
                       kind='repair_arc')
        self._path_row(f, 2, 'Save fixed copy as:', self.rp_out, [('Choose…', self._rp_pick_out)],
                       kind='save_as')
        ttk.Button(f, text='Repair', style='Big.TButton', command=self.do_repair).grid(
            row=3, column=0, columnspan=4, sticky='e', pady=(10, 0))

    def _build_list_tab(self):
        f = ttk.Frame(self.nb, padding=12)
        self.nb.add(f, text='  What’s inside  ')
        self.ls_arc = tk.StringVar()
        self._path_row(f, 0, 'Archive:', self.ls_arc, [('Choose…', lambda: self._pick_archive(self.ls_arc))],
                       kind='archive')
        ttk.Button(f, text='Show contents', style='Big.TButton', command=self.do_list).grid(
            row=0, column=3, sticky='e', padx=(4, 0))
        frow = ttk.Frame(f)
        frow.grid(row=1, column=0, columnspan=4, sticky='ew', pady=(8, 0))
        ttk.Label(frow, text='Search:').pack(side='left')
        self.ls_filter = tk.StringVar()
        ttk.Entry(frow, textvariable=self.ls_filter, width=30).pack(side='left', padx=6)
        self.ls_filter.trace_add('write', lambda *_: self._render_tree())
        self.ls_count = ttk.Label(frow, text='', style='Hint.TLabel')
        self.ls_count.pack(side='left', padx=6)
        ttk.Button(frow, text='Extract selected…', command=self._ls_send_to_unpack).pack(side='right')
        cols = ('size',)
        self.ls_tree = ttk.Treeview(f, columns=cols, height=7, selectmode='extended')
        self.ls_tree.heading('#0', text='File  \u2195', command=lambda: self._ls_sort_by('name'))
        self.ls_tree.heading('size', text='Size  \u2195', command=lambda: self._ls_sort_by('size'))
        self.ls_tree.column('#0', width=480, stretch=True)
        self.ls_tree.column('size', width=110, anchor='e', stretch=False)
        self.ls_tree.grid(row=2, column=0, columnspan=4, sticky='nsew', pady=(6, 0))
        sb = ttk.Scrollbar(f, orient='vertical', command=self.ls_tree.yview)
        sb.grid(row=2, column=4, sticky='ns', pady=(6, 0))
        self.ls_tree.configure(yscrollcommand=sb.set)
        f.rowconfigure(2, weight=1)

    def _build_bottom(self):
        bar = ttk.Frame(self, padding=(10, 0, 10, 0))
        bar.pack(fill='x')
        self.status = ttk.Label(bar, text='Ready.', font=('TkDefaultFont', 11, 'bold'))
        self.status.pack(side='left')
        self.cancel_btn = ttk.Button(bar, text='Cancel', command=self.cancel, state='disabled')
        self.cancel_btn.pack(side='right')
        ttk.Button(bar, text='Save log…', command=self._save_log).pack(side='right', padx=(0, 6))
        self.show_details = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text='Technical details', variable=self.show_details,
                        command=self._apply_details).pack(side='right', padx=(0, 10))
        self.elapsed = ttk.Label(bar, text='', style='Hint.TLabel')
        self.elapsed.pack(side='right', padx=8)
        self.progress = ttk.Progressbar(self, mode='indeterminate')
        self.progress.pack(fill='x', padx=10, pady=(6, 6))

        logf = ttk.Frame(self, padding=(10, 0, 10, 10))
        logf.pack(fill='both', expand=True)
        self.log = tk.Text(logf, height=12, wrap='word', state='disabled', relief='solid', borderwidth=1)
        self.log.pack(side='left', fill='both', expand=True)
        sb = ttk.Scrollbar(logf, orient='vertical', command=self.log.yview)
        sb.pack(side='right', fill='y')
        self.log.configure(yscrollcommand=sb.set)
        self.log.tag_configure('good', foreground='#1a7f37', font=('TkDefaultFont', 10, 'bold'))
        self.log.tag_configure('bad', foreground='#b42318', font=('TkDefaultFont', 10, 'bold'))
        self.log.tag_configure('dim', foreground='#777777')
        self.log.tag_configure('cmd', foreground='#555555', font=('TkFixedFont', 9))
        self.log.tag_configure('details', elide=True)

    # ---- small UI helpers --------------------------------------------
    def _refresh_rdc4_label(self):
        if self.rdc4:
            self.rdc4_label.configure(text='Using ' + self.rdc4, style='Hint.TLabel')
        else:
            self.rdc4_label.configure(text='rdc4.py not found. Click "Find rdc4.py…" and pick it.',
                                      style='Bad.TLabel')

    def _pick_rdc4(self):
        p = filedialog.askopenfilename(title='Find rdc4.py', filetypes=[('rdc4.py', 'rdc4.py'), ('Python', '*.py')])
        if p:
            self.rdc4 = os.path.abspath(p)
            self.settings['rdc4_path'] = self.rdc4
            save_settings(self.settings)
            self._refresh_rdc4_label()
            self._probe_caps_async()

    def _probe_caps_async(self):
        path = self.rdc4
        if not path or not os.path.isfile(path):
            return

        def work():
            self.events.put(('caps', path, probe_capabilities(sys.executable, path), None))
        threading.Thread(target=work, daemon=True).start()

    def _ensure_caps(self):
        # Normally already known from the background check at start-up; otherwise ask now (about 1 second).
        if self.caps_for != self.rdc4:
            self.caps = probe_capabilities(sys.executable, self.rdc4)
            self.caps_for = self.rdc4

    def _start_dir(self):
        d = self.settings.get('last_dir', '')
        return d if d and os.path.isdir(d) else os.path.expanduser('~')

    def _remember(self, path):
        if path:
            d = path if os.path.isdir(path) else os.path.dirname(path)
            if d:
                self.settings['last_dir'] = d
                save_settings(self.settings)

    def _pick_dir(self, var, title):
        p = filedialog.askdirectory(title=title, initialdir=self._start_dir())
        if p:
            var.set(p)
            self._remember(p)

    def _pick_archive(self, var, suggest_repair=False):
        p = filedialog.askopenfilename(title='Choose an archive', initialdir=self._start_dir(),
                                       filetypes=[('RDC archives', '*.rdc4 *.rdc3 *.rdc'), ('All files', '*')])
        if p:
            self._set_archive(var, p, suggest_repair)

    def _set_archive(self, var, p, suggest_repair=False):
        var.set(p)
        self._remember(p)
        if suggest_repair and self.rp_out.get().strip() in ('', self._rp_auto):
            # Fill (or refresh our own earlier suggestion) but never replace a name the person typed.
            base, ext = os.path.splitext(p)
            cand = base + '-repaired' + (ext or '.rdc4')
            n = 2
            while os.path.exists(cand):
                cand = '%s-repaired-%d%s' % (base, n, ext or '.rdc4')
                n += 1
            self._rp_auto = cand
            self.rp_out.set(cand)

    def _on_up_arc_changed(self):
        # A file pick from one archive must not silently apply to another archive.
        if self.up_only and self.up_arc.get().strip() != self.up_only_arc:
            self.up_only = []
            self._update_only_label()

    def _set_pack_source(self, p):
        self.pk_src.set(p)
        self._remember(p)
        if not self.pk_out.get():
            self.pk_out.set(self._suggest_archive_name(p))

    def _suggest_archive_name(self, src):
        base = os.path.basename(os.path.normpath(src)) or 'archive'
        parent = os.path.dirname(os.path.normpath(src)) or os.path.expanduser('~')
        cand = os.path.join(parent, base + '.rdc4')
        n = 2
        while os.path.exists(cand):
            cand = os.path.join(parent, '%s-%d.rdc4' % (base, n))
            n += 1
        return cand

    def _pk_pick_folder(self):
        p = filedialog.askdirectory(title='Choose the folder to compress', initialdir=self._start_dir())
        if p:
            self._set_pack_source(p)

    def _pk_pick_file(self):
        p = filedialog.askopenfilename(title='Choose the file to compress', initialdir=self._start_dir())
        if p:
            self._set_pack_source(p)

    def _pk_pick_out(self):
        src = self.pk_src.get().strip()
        init = self._suggest_archive_name(src) if src else os.path.join(self._start_dir(), 'archive.rdc4')
        p = filedialog.asksaveasfilename(title='Save archive as', initialdir=os.path.dirname(init),
                                         initialfile=os.path.basename(init), defaultextension='.rdc4',
                                         filetypes=[('RDC archive', '*.rdc4')], confirmoverwrite=False)
        if p:
            self.pk_out.set(p)

    def _rp_pick_out(self):
        p = filedialog.asksaveasfilename(title='Save fixed copy as', initialdir=self._start_dir(),
                                         defaultextension='.rdc4', filetypes=[('RDC archive', '*.rdc4')],
                                         confirmoverwrite=False)
        if p:
            self.rp_out.set(p)

    def _up_pick_some(self):
        arc = self.up_arc.get().strip()
        if not self._check_archive(arc):
            return

        def show(result):
            if not result or 'files' not in result:
                return
            win = tk.Toplevel(self)
            win.title('Pick the files to extract')
            win.geometry('560x420')
            ttk.Label(win, text='Select one or more files (Ctrl-click or Shift-click for several).',
                      padding=8).pack(fill='x')
            lb = tk.Listbox(win, selectmode='extended')
            lb.pack(fill='both', expand=True, padx=8)
            paths = [x['path'] for x in result['files']]
            for p in paths:
                lb.insert('end', p)
            for i, p in enumerate(paths):
                if p in self.up_only:
                    lb.selection_set(i)

            def ok():
                self.up_only = [paths[i] for i in lb.curselection()]
                self.up_only_arc = arc
                self._update_only_label()
                win.destroy()

            def all_files():
                self.up_only = []
                self._update_only_label()
                win.destroy()

            btns = ttk.Frame(win, padding=8)
            btns.pack(fill='x')
            ttk.Button(btns, text='Use selected', command=ok).pack(side='right')
            ttk.Button(btns, text='Extract everything', command=all_files).pack(side='right', padx=6)
            win.transient(self)
            win.grab_set()

        self._run(['ls', arc], 'Reading the list of files…', self._summ_list_quiet, then=show)

    def _update_only_label(self):
        if self.up_only:
            n = len(self.up_only)
            self.up_only_label.configure(text='%d file%s picked: %s' % (
                n, '' if n == 1 else 's', ', '.join(self.up_only[:3]) + (' …' if n > 3 else '')))
        else:
            self.up_only_label.configure(text='All files will be extracted.')

    # ---- drag and drop -----------------------------------------------
    def _setup_dnd(self):
        if not self.dnd:
            self.write('Tip: drag and drop is off. To turn it on, see "Drag and drop" in HOW-TO-RUN.md. '
                       'The Choose buttons work either way.', 'dim')
            return
        try:
            for entry, kind, var in self.drop_fields:
                entry.drop_target_register(DND_FILES)
                entry.dnd_bind('<<Drop>>', lambda e, k=kind, v=var: self._on_drop_field(e, k, v))
            self.drop_target_register(DND_FILES)
            self.dnd_bind('<<Drop>>', self._on_drop_window)
        except Exception as exc:
            self.dnd = False
            self.write('Drag and drop could not be turned on (%s). The Choose buttons still work.' % exc, 'dim')
            return
        self.write('Tip: you can drag files and folders from your file manager onto a box, '
                   'or anywhere on this window.', 'dim')

    def _dropped_paths(self, event):
        try:
            items = self.tk.splitlist(event.data)
        except tk.TclError:
            items = [event.data]
        paths = []
        for p in items:
            p = str(p).strip()
            if p.startswith('file://'):
                p = file_uri_to_path(p)
            if p:
                paths.append(os.path.normpath(p))
        return paths

    def _one(self, paths, what):
        if len(paths) > 1:
            messagebox.showinfo(APP_TITLE, 'You dropped %d items, but only one %s can be used here, so the first '
                                'one was taken:\n%s\n\nTo pack several things together, put them in one folder '
                                'and drop that folder.' % (len(paths), what, paths[0]), parent=self)
        return paths[0]

    def _on_drop_field(self, event, kind, var):
        paths = self._dropped_paths(event)
        if paths:
            self.apply_drop(paths, kind, var)
        return getattr(event, 'action', 'copy')

    def _on_drop_window(self, event):
        paths = self._dropped_paths(event)
        if paths:
            self.apply_drop(paths, None, None)
        return getattr(event, 'action', 'copy')

    def apply_drop(self, paths, kind=None, var=None):
        """Put dropped paths where they belong. kind=None means 'dropped somewhere on the window'."""
        tab = self.nb.index(self.nb.select())
        if kind is None:
            first = paths[0]
            if tab == 0:
                if len(paths) == 1 and is_archive_name(first):
                    # An archive dropped on the Pack tab almost always means "open it".
                    self.nb.select(1)
                    self._set_archive(self.up_arc, first)
                    self.set_status('Archive added to the Unpack tab.')
                    return
                kind = 'pack_src'
            elif tab == 1:
                files = [p for p in paths if os.path.isfile(p)]
                dirs = [p for p in paths if os.path.isdir(p)]
                if files:
                    self.apply_drop(files, 'archive', self.up_arc)
                if dirs:
                    self.apply_drop(dirs, 'dest_dir', self.up_dest)
                return
            elif tab == 2:
                kind = 'verify_add'
            elif tab == 3:
                kind, var = 'repair_arc', self.rp_arc
            else:
                kind, var = 'archive', self.ls_arc
        if kind == 'verify_add':
            self._vf_add(paths)
            return
        if kind == 'pack_src':
            p = self._one(paths, 'folder or file')
            if not os.path.exists(p):
                return
            self.nb.select(0)
            self._set_pack_source(p)
        elif kind in ('archive', 'repair_arc'):
            p = self._one(paths, 'archive')
            if os.path.isdir(p):
                messagebox.showwarning(APP_TITLE, 'That is a folder. Drop an archive file (.rdc4) here.', parent=self)
                return
            self._set_archive(var, p, suggest_repair=(kind == 'repair_arc'))
            if var is self.ls_arc and self.proc is None:
                self.do_list()
        elif kind == 'dest_dir':
            p = self._one(paths, 'folder')
            if not os.path.isdir(p):
                messagebox.showwarning(APP_TITLE, 'Drop a folder here (the place to extract into).', parent=self)
                return
            var.set(p)
            self._remember(p)
        elif kind == 'save_as':
            p = self._one(paths, 'folder')
            folder = p if os.path.isdir(p) else os.path.dirname(p)
            if var is self.pk_out:
                src = self.pk_src.get().strip()
                name = os.path.basename(self._suggest_archive_name(src)) if src else 'archive.rdc4'
            else:
                src = self.rp_arc.get().strip()
                name = (os.path.splitext(os.path.basename(src))[0] + '-repaired.rdc4') if src else 'repaired.rdc4'
            var.set(os.path.join(folder, name))

    def _apply_details(self):
        self.log.tag_configure('details', elide=not self.show_details.get())
        self.log.see('end')

    def _save_log(self):
        p = filedialog.asksaveasfilename(title='Save the log as', initialdir=self._start_dir(),
                                         initialfile='rdc-log-%s.txt' % time.strftime('%Y-%m-%d-%H%M'),
                                         defaultextension='.txt', filetypes=[('Text file', '*.txt')])
        if not p:
            return
        try:
            with open(p, 'w', encoding='utf-8') as f:
                f.write(self.log.get('1.0', 'end'))
            self.set_status('Log saved.', 'Good.TLabel')
        except OSError as exc:
            messagebox.showerror(APP_TITLE, 'Could not save the log:\n%s' % exc, parent=self)

    def write(self, text, tag=None):
        self.log.configure(state='normal')
        self.log.insert('end', text + '\n', tag or ())
        lines = int(self.log.index('end-1c').split('.')[0])
        if lines > LOG_LINE_LIMIT + 500:        # trim in batches, not on every line
            cut = lines - LOG_LINE_LIMIT
            self.log.delete('1.0', '%d.0' % (cut + 1))
            self.log_dropped += cut
        self.log.see('end')
        self.log.configure(state='disabled')

    def set_status(self, text, style=None):
        self.status.configure(text=text, style=style or 'TLabel')

    # ---- validation --------------------------------------------------
    def _need(self, cond, msg):
        if not cond:
            messagebox.showwarning(APP_TITLE, msg, parent=self)
        return cond

    def _check_archive(self, arc):
        return (self._need(arc, 'Choose an archive first.') and
                self._need(os.path.isfile(arc), 'That archive file does not exist:\n' + arc))

    # ---- actions -----------------------------------------------------
    def do_pack(self):
        src = self.pk_src.get().strip()
        out = self.pk_out.get().strip()
        if not (self._need(src, 'Choose a folder or file to compress.') and
                self._need(os.path.exists(src), 'This does not exist:\n' + src) and
                self._need(out, 'Choose where to save the archive.')):
            return
        if not out.lower().endswith(('.rdc4', '.rdc3', '.rdc')):
            out += '.rdc4'
            self.pk_out.set(out)
        if not self._need(not os.path.exists(out),
                          'A file with this name already exists:\n%s\n\nrdc4 never overwrites. '
                          'Pick a different name.' % out):
            return
        if os.path.isdir(src) and path_inside(out, src):
            if not messagebox.askyesno(APP_TITLE, 'The archive will be saved inside the folder you are compressing.\n'
                                       'It is usually better to save it somewhere else. Continue anyway?',
                                       parent=self):
                return
        args = ['pack', src, out]
        if self.pk_level.get().startswith('Faster'):
            args += ['--level', '9']
        try:
            th = int(self.pk_threads.get())
        except (tk.TclError, ValueError):
            th = 1
        if th > 1:
            args += ['--threads', str(th)]
        args += dict(REPAIR_CHOICES).get(self.pk_parity.get(), [])
        if self.pk_encrypt.get():
            if not self._need(self.password.get(), 'Type a password at the top to encrypt the archive.'):
                return
            if not self._confirm_password():
                return
            args += ['--encrypt']
        self._run(args, 'Packing… (big folders can take a while)', self._summ_pack,
                  use_password=self.pk_encrypt.get())

    def _confirm_password(self):
        win = tk.Toplevel(self)
        win.title('Confirm password')
        win.resizable(False, False)
        ttk.Label(win, text='Type the password again. If you forget it, the archive cannot be opened.',
                  padding=10, wraplength=360).pack()
        v = tk.StringVar()
        e = ttk.Entry(win, textvariable=v, show='•', width=30)
        e.pack(padx=10)
        e.focus_set()
        result = {'ok': False}

        def ok(_evt=None):
            if v.get() == self.password.get():
                result['ok'] = True
                win.destroy()
            else:
                messagebox.showerror(APP_TITLE, 'The passwords do not match.', parent=win)

        b = ttk.Frame(win, padding=10)
        b.pack(fill='x')
        ttk.Button(b, text='OK', command=ok).pack(side='right')
        ttk.Button(b, text='Cancel', command=win.destroy).pack(side='right', padx=6)
        e.bind('<Return>', ok)
        win.transient(self)
        win.grab_set()
        self.wait_window(win)
        return result['ok']

    def do_unpack(self):
        arc = self.up_arc.get().strip()
        dest = self.up_dest.get().strip()
        if not (self._check_archive(arc) and self._need(dest, 'Choose a folder to extract into.')):
            return
        args = ['unpack', arc, dest]
        if self.up_recover.get():
            args.append('--recover')
        for p in self.up_only:
            args += ['--only', p]
        self._run(args, 'Unpacking…', self._summ_unpack)

    def do_verify(self):
        items = list(self.vf_list.get(0, 'end'))
        if not items and self.vf_arc.get().strip():
            items = [self.vf_arc.get().strip()]
        if not self._need(items, 'Add an archive to the list first (Add archives…, or drag one in).'):
            return
        missing = [a for a in items if not os.path.isfile(a)]
        if not self._need(not missing, 'These archives no longer exist:\n' + '\n'.join(missing)):
            return
        self.vf_queue = items[:]
        self.vf_results = []
        self._verify_next()

    def _verify_next(self):
        if not self.vf_queue:
            self._verify_batch_summary()
            return
        arc = self.vf_queue.pop(0)
        total = len(self.vf_results) + len(self.vf_queue) + 1
        self.vf_arc.set(arc)
        label = 'Checking the archive…' if total == 1 else 'Checking %s (%d of %d)…' % (
            os.path.basename(arc), len(self.vf_results) + 1, total)
        started = self._run(['verify', arc], label, self._summ_verify, after=self._verify_after)
        if not started:
            self.vf_queue = []

    def _verify_after(self, outcome):
        self.vf_results.append((self.vf_arc.get(), outcome))
        if outcome == 'cancelled':
            if self.vf_queue:
                self.write('The other %d archive(s) in the list were not checked.' % len(self.vf_queue), 'dim')
            self.vf_queue = []
            return
        self.after(50, self._verify_next)

    def _verify_batch_summary(self):
        res = self.vf_results
        if len(res) < 2:
            return
        good = [a for a, o in res if o == 'ok']
        bad = [a for a, o in res if o == 'damaged']
        err = [a for a, o in res if o not in ('ok', 'damaged')]
        tag = 'good' if not bad and not err else 'bad'
        self.write('')
        self.write('Checked %d archives: %d healthy, %d need repair, %d could not be checked.' % (
            len(res), len(good), len(bad), len(err)), tag)
        for a in bad:
            self.write('    needs repair: ' + a)
        for a in err:
            self.write('    could not check: ' + a)
        if bad:
            self._set_archive(self.rp_arc, bad[0], suggest_repair=True)
            self.write('  The first damaged one is filled in on the Repair tab.')
        self.set_status('All healthy.' if tag == 'good' else 'Some archives need attention.',
                        'Good.TLabel' if tag == 'good' else 'Bad.TLabel')

    def _vf_add_dialog(self):
        ps = filedialog.askopenfilenames(title='Choose archives to check', initialdir=self._start_dir(),
                                         filetypes=[('RDC archives', '*.rdc4 *.rdc3 *.rdc'), ('All files', '*')])
        if ps:
            self._vf_add(list(self.tk.splitlist(ps)) if isinstance(ps, str) else list(ps))

    def _vf_add(self, paths):
        have = set(self.vf_list.get(0, 'end'))
        skipped = []
        for p in paths:
            if os.path.isdir(p):
                skipped.append(p)
                continue
            if p not in have:
                self.vf_list.insert('end', p)
                have.add(p)
                self._remember(p)
        if skipped:
            messagebox.showwarning(APP_TITLE, 'Folders cannot be verified, only archive files. Skipped:\n'
                                   + '\n'.join(skipped[:10]), parent=self)

    def _vf_remove(self):
        for i in reversed(self.vf_list.curselection()):
            self.vf_list.delete(i)

    def do_repair(self):
        arc = self.rp_arc.get().strip()
        out = self.rp_out.get().strip()
        if not (self._check_archive(arc) and self._need(out, 'Choose where to save the fixed copy.') and
                self._need(not os.path.exists(out), 'A file with this name already exists:\n%s\n\n'
                           'Pick a different name.' % out)):
            return
        self._run(['repair', arc, out], 'Repairing…', self._summ_repair)

    def do_list(self):
        arc = self.ls_arc.get().strip()
        if self._check_archive(arc):
            self._run(['ls', arc], 'Reading the list of files…', self._summ_list)

    # ---- running rdc4 ------------------------------------------------
    def _run(self, args, status, summarize, use_password=True, then=None, after=None):
        if self.proc is not None:
            messagebox.showinfo(APP_TITLE, 'Something is already running. Wait for it or press Cancel.', parent=self)
            return False
        if not self.rdc4 or not os.path.isfile(self.rdc4):
            messagebox.showerror(APP_TITLE, 'rdc4.py was not found. Click "Find rdc4.py…" at the top and pick it.',
                                 parent=self)
            return False
        self._ensure_caps()
        args = list(args)
        if self.caps['progress'] and args[0] in ('pack', 'unpack', 'verify', 'repair'):
            args.append('--progress')
        env = dict(os.environ)
        env['PYTHONIOENCODING'] = 'utf-8'
        env.pop('RDC_PASSWORD', None)
        stdin_payload = None
        if self.password.get() and (use_password or args[0] != 'pack'):
            if self.caps['password_stdin']:
                # Safer: the password goes through a private pipe, not the process environment.
                args.append('--password-stdin')
                stdin_payload = self.password.get() + '\n'
            else:
                env['RDC_PASSWORD'] = self.password.get()
        cmd = [sys.executable, '-u', self.rdc4] + args
        kwargs = {}
        if sys.platform == 'win32':
            kwargs['creationflags'] = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        self.write('')
        self.write('▶ ' + status, None)
        self.write('  ' + subprocess.list2cmdline(['rdc4.py'] + args), ('cmd', 'details'))
        try:
            self.proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                         stdin=subprocess.PIPE if stdin_payload else subprocess.DEVNULL,
                                         env=env, cwd=os.path.dirname(self.rdc4), text=True, encoding='utf-8',
                                         errors='replace', **kwargs)
            if stdin_payload:
                try:
                    self.proc.stdin.write(stdin_payload)
                    self.proc.stdin.close()
                except OSError:
                    pass
            stdin_payload = None
        except OSError as exc:
            self.proc = None
            self.write('Could not start rdc4: %s' % exc, 'bad')
            return False
        self.on_done = (summarize, then, args[0], after)
        self.cancelled = False
        self.started = time.time()
        self.set_status(status)
        self.run_status = status
        self.prog_stage = None
        self.latest_progress = None
        self.prog_detail = ''
        self.progress.configure(mode='indeterminate', value=0)
        self.progress.start(12)
        self.cancel_btn.configure(state='normal')
        proc = self.proc
        out_parts, err_lines = [], []

        def read_stdout():
            out_parts.append(proc.stdout.read())

        def read_stderr():
            # Progress lines become events for the bar; everything else is kept for the result.
            for line in proc.stderr:
                ev = parse_progress_line(line)
                if ev is not None:
                    # One shared slot, not a queue: however fast lines arrive, the window only ever
                    # has the newest position waiting, so memory and redraw work stay constant.
                    self.latest_progress = ev
                else:
                    err_lines.append(line)

        def waiter():
            t1 = threading.Thread(target=read_stdout, daemon=True)
            t2 = threading.Thread(target=read_stderr, daemon=True)
            t1.start(); t2.start(); t1.join(); t2.join()
            proc.wait()
            self.events.put(('done', proc.returncode, ''.join(out_parts), ''.join(err_lines)))

        threading.Thread(target=waiter, daemon=True).start()
        return True

    def cancel(self):
        if self.proc is not None and self.proc.poll() is None:
            self.cancelled = True
            self.proc.terminate()
            self.write('Cancel requested. Nothing half-written is kept: rdc4 only saves finished archives.', 'dim')

    def _poll(self):
        latest, self.latest_progress = self.latest_progress, None
        try:
            for _ in range(EVENTS_PER_TICK):
                kind, a, b, c = self.events.get_nowait()
                if kind == 'done':
                    latest = None
                    self._finish(a, b, c)
                elif kind == 'caps':
                    if a == self.rdc4:
                        self.caps, self.caps_for = b, a
        except queue.Empty:
            pass
        if latest is not None and self.proc is not None:
            self._show_progress(latest)
        if self.proc is not None:
            secs = '%ds' % int(time.time() - self.started)
            self.elapsed.configure(text=self.prog_detail or secs)
        self.after(100, self._poll)

    def _show_progress(self, ev):
        stage, done, total = ev.get('stage'), ev.get('done', 0), ev.get('total', 0)
        now = time.time()
        if stage != self.prog_stage:
            self.prog_stage, self.prog_t0, self.prog_d0 = stage, now, done
        if self.progress.cget('mode') != 'determinate':
            self.progress.stop()
            self.progress.configure(mode='determinate', maximum=1000)
        frac = (done / total) if total else 1.0
        self.progress.configure(value=int(1000 * min(1.0, frac)))
        name = STAGE_NAMES.get(stage, stage or 'Working')
        if stage == 'verify' and self.on_done and self.on_done[2] == 'repair':
            name = 'Checking the repaired copy'
        self.set_status('%s\u2026 %d%%' % (name, int(100 * frac)))
        detail = ''
        if total:
            detail = '%s of %s' % (human_size(done), human_size(total))
            dt = now - self.prog_t0
            if dt > 2 and done > self.prog_d0:
                speed = (done - self.prog_d0) / dt
                left = (total - done) / speed
                detail += ', about %s left' % (('%d min' % round(left / 60)) if left >= 90 else
                                                ('%d s' % max(1, round(left))))
        self.prog_detail = detail

    def _finish(self, rc, out, err):
        self.proc = None
        self.progress.stop()
        self.progress.configure(mode='determinate', value=0)
        self.cancel_btn.configure(state='disabled')
        secs = time.time() - self.started
        self.elapsed.configure(text='took %.1fs' % secs)
        summarize, then, cmd, after = self.on_done or (None, None, '', None)
        self.on_done = None
        result_out = parse_json_lines(out)
        result_err = parse_json_lines(err)
        if self.cancelled:
            self.cancelled = False
            self.set_status('Cancelled.', 'Bad.TLabel')
            self.write('Cancelled.', 'bad')
            if after:
                after('cancelled')
            return
        outcome = 'failed'
        if rc == 0 and result_out is not None:
            outcome = 'ok'
            try:
                summarize(result_out)
            except Exception as exc:  # never lose the result because of a display problem
                self.write('Done. (Could not format the summary: %s)' % exc, 'good')
                self.set_status('Done.', 'Good.TLabel')
            if then:
                then(result_out)
        elif cmd == 'verify' and rc == 4 and result_out is not None:
            outcome = 'damaged'
            self._summ_verify(result_out)
        elif cmd == 'unpack' and rc == 3 and result_err is not None:
            outcome = 'damaged'
            self._summ_unpack(result_err)
        else:
            msg = friendly_error(result_err, err)
            self.set_status('Failed.', 'Bad.TLabel')
            self.write('✖ ' + msg, 'bad')
        tail = (out + err).strip()
        if tail:
            self.write('  details: ' + (tail if len(tail) < 4000 else tail[:4000] + ' …'), ('dim', 'details'))
        if after:
            after(outcome)

    # ---- result summaries -------------------------------------------
    def _summ_pack(self, r):
        orig = r.get('original_bytes', 0)
        stored = r.get('stored_bytes', 0)
        pct = (100.0 * stored / orig) if orig else 0
        self.set_status('Packed.', 'Good.TLabel')
        self.write('✔ Archive saved: %s' % self.pk_out.get(), 'good')
        self.write('  %d files, %s → %s (%.0f%% of the original size)' % (
            r.get('files', 0), human_size(orig), human_size(stored), pct))
        extras = []
        if r.get('dedup_saved_bytes'):
            extras.append('%s of repeated data stored only once' % human_size(r['dedup_saved_bytes']))
        extras.append('encrypted' if r.get('encrypted') else 'not encrypted')
        extras.append('with repair data' if r.get('parity_bytes') else 'no repair data')
        self.write('  ' + ', '.join(extras))
        self.pk_out.set('')

    def _summ_unpack(self, r):
        damaged = r.get('damaged') or []
        if damaged:
            self.set_status('Extracted, but some files are damaged.', 'Bad.TLabel')
            self.write('⚠ Extracted %d files into %s, but %d could not be restored correctly:' % (
                r.get('files', 0), self.up_dest.get(), len(damaged)), 'bad')
            for d in damaged[:50]:
                self.write('    ' + (d if isinstance(d, str) else json.dumps(d)))
            self.write('  Try the Repair tab on this archive, then unpack the repaired copy.')
        else:
            self.set_status('Extracted.', 'Good.TLabel')
            self.write('✔ Extracted %d files (%s) into %s' % (
                r.get('files', 0), human_size(r.get('bytes', 0)), self.up_dest.get()), 'good')
        for w in (r.get('name_warnings') or [])[:20]:
            self.write('  note: %s' % (w if isinstance(w, str) else json.dumps(w)), 'dim')

    def _summ_verify(self, r):
        if r.get('ok') and not r.get('needs_repair'):
            self.set_status('Archive is healthy.', 'Good.TLabel')
            msg = '✔ All %d files check out. The archive is healthy.' % r.get('files', 0)
            if self.vf_results or self.vf_queue:
                msg = '✔ %s: all %d files check out.' % (os.path.basename(self.vf_arc.get()), r.get('files', 0))
            if r.get('parity_repairs_used'):
                msg += ' (Some small damage was fixed on the fly by the repair data; consider using Repair.)'
            self.write(msg, 'good')
        else:
            self.set_status('Archive needs repair.', 'Bad.TLabel')
            if self.vf_results or self.vf_queue:
                self.write('  ' + os.path.basename(self.vf_arc.get()) + ':', 'bad')
            self.write('✖ The archive is damaged. Bad pieces: %d shard(s), %d pack(s), %d chunk(s).' % (
                len(r.get('bad_shards') or []), len(r.get('bad_packs') or []), len(r.get('bad_chunks') or [])), 'bad')
            self.write('  Go to the Repair tab to write a fixed copy (it is filled in for you).')
            self._set_archive(self.rp_arc, self.vf_arc.get(), suggest_repair=True)
        for w in (r.get('warnings') or [])[:20]:
            self.write('  note: %s' % (w if isinstance(w, str) else json.dumps(w)), 'dim')

    def _summ_repair(self, r):
        re = r.get('reverify') or {}
        fixed = len(r.get('repaired_groups') or [])
        if re.get('ok'):
            self.set_status('Repaired copy saved.', 'Good.TLabel')
            if fixed:
                self.write('✔ Fixed %d damaged area(s). The repaired copy checks out: %s' % (
                    fixed, self.rp_out.get()), 'good')
            else:
                self.write('✔ Nothing was damaged. A checked copy was saved: %s' % self.rp_out.get(), 'good')
        else:
            self.set_status('Repair could not fix everything.', 'Bad.TLabel')
            self.write('✖ The copy was written, but it still does not check out. Too much of the archive '
                       'is damaged for the repair data. Use Unpack with Recover mode to save what is good.', 'bad')

    def _fill_tree(self, r):
        self.ls_result = r
        self.ls_result_arc = self.ls_arc.get().strip()
        self._render_tree()

    def _ls_sort_by(self, key):
        cur, rev = self.ls_sort
        self.ls_sort = (key, (not rev) if cur == key else (key == 'size'))
        self._render_tree()

    def _render_tree(self):
        t = self.ls_tree
        t.delete(*t.get_children())
        r = self.ls_result
        if not r:
            self.ls_count.configure(text='')
            return
        files = list(r.get('files') or [])
        key, rev = self.ls_sort
        if key == 'size':
            files.sort(key=lambda x: (x['size'], x['path']), reverse=rev)
        else:
            files.sort(key=lambda x: x['path'].lower(), reverse=rev)
        needle = self.ls_filter.get().strip().lower()
        if needle:
            # Searching shows a flat list of matching files with their full paths.
            hits = [f for f in files if needle in f['path'].lower()]
            for f in hits:
                t.insert('', 'end', iid='f:' + f['path'], text=f['path'], values=(human_size(f['size']),))
            self.ls_count.configure(text='%d of %d files match' % (len(hits), len(files)))
            return
        nodes = {'': ''}

        def ensure(dirpath):
            if dirpath in nodes:
                return nodes[dirpath]
            parent, _, name = dirpath.rpartition('/')
            pid = ensure(parent)
            nodes[dirpath] = t.insert(pid, 'end', iid='d:' + dirpath, text=name + '/', open=False)
            return nodes[dirpath]

        for d in sorted(r.get('dirs') or [], key=str.lower):
            ensure(d)
        for f in files:
            parent, _, name = f['path'].rpartition('/')
            t.insert(ensure(parent), 'end', iid='f:' + f['path'], text=name, values=(human_size(f['size']),))
        self.ls_count.configure(text='%d files' % len(files))

    def _ls_selected_files(self):
        r = self.ls_result or {}
        allpaths = [f['path'] for f in (r.get('files') or [])]
        picked = []
        for iid in self.ls_tree.selection():
            if iid.startswith('f:'):
                picked.append(iid[2:])
            elif iid.startswith('d:'):
                pre = iid[2:] + '/'
                picked.extend(p for p in allpaths if p.startswith(pre))
        seen = set()
        return [p for p in picked if not (p in seen or seen.add(p))]

    def _ls_send_to_unpack(self):
        if not self.ls_result:
            messagebox.showinfo(APP_TITLE, 'Press "Show contents" first, then select the files you want.', parent=self)
            return
        picked = self._ls_selected_files()
        if not picked:
            messagebox.showinfo(APP_TITLE, 'Select one or more files (or folders) in the list first. '
                                'Ctrl-click or Shift-click selects several.', parent=self)
            return
        arc = getattr(self, 'ls_result_arc', '') or self.ls_arc.get().strip()
        self.up_arc.set(arc)
        self.up_only = picked
        self.up_only_arc = arc
        self._update_only_label()
        self.nb.select(1)
        self.set_status('%d file(s) ready to extract. Choose a folder and press Unpack.' % len(picked))

    def _summ_list(self, r):
        self._fill_tree(r)
        self._summ_list_quiet(r)

    def _summ_list_quiet(self, r):
        self.set_status('Done.', 'Good.TLabel')
        par = r.get('parity')
        self.write('✔ %d files, %s in total. %s, %s.' % (
            len(r.get('files') or []), human_size(r.get('total', 0)),
            'Encrypted' if r.get('encrypted') else 'Not encrypted',
            ('has repair data (%s,%s)' % (par[0], par[1])) if par else 'no repair data'), 'good')

    def _on_close(self):
        if self.proc is not None and self.proc.poll() is None:
            if not messagebox.askyesno(APP_TITLE, 'Something is still running. Stop it and close?', parent=self):
                return
            self.proc.terminate()
        self.destroy()


def enable_windows_dpi_awareness():
    """Sharp text on Windows screens set to 125%/150% scaling (no effect elsewhere)."""
    if sys.platform != 'win32':
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def main():
    enable_windows_dpi_awareness()
    app = App()
    app.geometry('900x680')
    app.mainloop()


if __name__ == '__main__':
    main()
