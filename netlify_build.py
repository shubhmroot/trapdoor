"""Export Trapdoor's Flask-rendered page and assets for Netlify's CDN."""

from pathlib import Path
import shutil

from app import app


ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"


def build() -> None:
    PUBLIC.mkdir(exist_ok=True)
    with app.test_client() as client:
        response = client.get("/")
    if response.status_code != 200:
        raise RuntimeError(f"Flask home page returned HTTP {response.status_code}")
    (PUBLIC / "index.html").write_bytes(response.data)

    assets = PUBLIC / "static"
    assets.mkdir(exist_ok=True)
    for asset in (ROOT / "static").iterdir():
        if asset.is_file():
            shutil.copy2(asset, assets / asset.name)


if __name__ == "__main__":
    build()

