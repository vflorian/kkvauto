"""Native file-open dialog (run as a separate process: python -m capscope.filedialog).

Prints the selected path on stdout (empty if cancelled). Running it in its own
process keeps Tk out of the server's threads."""
import sys


def main() -> None:
    try:
        import tkinter as tk
        from tkinter import filedialog
    except Exception as e:  # pragma: no cover - platform dependent
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(2)
    root = tk.Tk()
    root.withdraw()
    root.attributes("-topmost", True)
    path = filedialog.askopenfilename(title="Capture megnyitása", filetypes=[
        ("Capture", "*.pcap *.pcapng *.cap *.ntar *.gz"), ("Minden fájl", "*.*")])
    root.destroy()
    print(path or "")


if __name__ == "__main__":
    main()
