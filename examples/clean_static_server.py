from pathlib import Path

for name in ("index.html", "page.txt"):
    path = Path("/guest/www") / name
    try:
        print(path.read_text(), end="")
    except FileNotFoundError:
        pass
