# RDC Archiver: a window for rdc4.py

`rdc_gui.py` is a small desktop window for rdc4.py. It has five tabs:

- **Pack (compress):** pick a folder or file, pick where to save the archive, press Pack.
- **Unpack (extract):** pick an archive and an empty folder. You can pick only some files, and turn on Recover mode for damaged archives.
- **Verify (check):** checks every file in one or more archives without extracting anything. Add several (or drag several in) and they are checked one after another, with a summary at the end. A damaged one is filled in on the Repair tab for you.
- **Repair:** writes a fixed copy of a damaged archive. The original is left alone.
- **What's inside:** shows the files in an archive. Type in **Search** to find files, click the **File** or **Size** heading to sort, select files or folders and press **Extract selected…** to send just those to the Unpack tab.

**Drag and drop:** drag a folder or file from the file manager onto any box, or anywhere on the
window. Dropped anywhere, it goes where it makes sense for the tab you're on: on Pack it becomes the
thing to compress (an archive dropped there opens the Unpack tab instead); on Unpack an archive file
fills the archive box and a folder fills the destination; on the other tabs it fills the archive box,
and on What's inside the list appears right away.

The **Password** box at the top is used for encrypted archives. It is never saved to disk; **Clear** empties it.

The bottom box shows plain-English results. Tick **Technical details** to also see the exact rdc4 command and its raw output, and use **Save log…** to keep a copy of everything as a text file.

**Progress bar:** with the updated `rdc4.py` from this folder, the bar shows a real percentage and "about N min left", and the password is passed through a private pipe instead of the environment. With the original rdc4.py the window still works; the bar just moves back and forth. Speed and archive bytes are identical either way (see BENCHMARKS-AND-REVIEW.md).

## Ubuntu: one-time setup

Copy and paste each line into a Terminal, one at a time. This assumes you downloaded
`rdc_gui.py` into your Downloads folder.

```
sudo apt install -y python3-tk
```

```
cp ~/Downloads/rdc_gui.py ~/rdc/research-data-compress-v3.1.6/
```

For the progress bar, also install the updated rdc4.py. First keep a copy of your original (this line never overwrites an existing copy):

```
cp -n ~/rdc/research-data-compress-v3.1.6/rdc4.py ~/rdc/research-data-compress-v3.1.6/rdc4-original-3.1.6.py
```

Then copy in the new rdc4.py and its tests (download both from this folder to Downloads first):

```
cp ~/Downloads/rdc4.py ~/Downloads/test_gui_addon.py ~/rdc/research-data-compress-v3.1.6/
```

Optional check that everything passes on your machine (takes about 2 minutes):

```
cd ~/rdc/research-data-compress-v3.1.6 && .venv/bin/python -m pytest -q test_rdc4.py test_rdc3.py test_gui_addon.py
```

To go back to the original rdc4.py at any time:

```
cp ~/rdc/research-data-compress-v3.1.6/rdc4-original-3.1.6.py ~/rdc/research-data-compress-v3.1.6/rdc4.py
```

This one turns on drag and drop (it adds a small package to the rdc .venv only):

```
~/rdc/research-data-compress-v3.1.6/.venv/bin/python -m pip install tkinterdnd2
```

## Ubuntu: start the window

```
~/rdc/research-data-compress-v3.1.6/.venv/bin/python ~/rdc/research-data-compress-v3.1.6/rdc_gui.py
```

### Optional: add it to the Ubuntu app menu

Paste this once. After that, press the Super (Windows) key, type **RDC**, and click **RDC Archiver**.

```
mkdir -p ~/.local/share/applications && printf "[Desktop Entry]\nType=Application\nName=RDC Archiver\nExec=%s/rdc/research-data-compress-v3.1.6/.venv/bin/python %s/rdc/research-data-compress-v3.1.6/rdc_gui.py\nIcon=package-x-generic\nTerminal=false\n" "$HOME" "$HOME" > ~/.local/share/applications/rdc-archiver.desktop
```

## Windows

Put `rdc_gui.py` in the same folder as `rdc4.py` and start it with the Python that has the
requirements installed (Tkinter is already included with the python.org installer), for example
from that folder: `.venv\Scripts\python rdc_gui.py`. For drag and drop, also run
`.venv\Scripts\python -m pip install tkinterdnd2` once.

## If something goes wrong

- **"No module named tkinter"**: run the `sudo apt install -y python3-tk` line above.
- **"rdc4.py not found"** at the top of the window: click **Find rdc4.py…** and pick the rdc4.py file. It is remembered next time.
- **"rdc4 is missing a Python package"**: you started the window with the wrong Python. Use the exact start command above (it uses the `.venv` Python).
- **"drag and drop is off"** in the bottom box: run the `pip install tkinterdnd2` line above, then restart the window. The Choose buttons work either way.
- **The bar only moves back and forth, no percentage**: the window is using the original rdc4.py. Copy in the updated one (above) and restart the window.
- rdc4 never overwrites anything. If it says something already exists, pick a new archive name or an empty folder.
