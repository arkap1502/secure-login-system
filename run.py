import os

from dotenv import load_dotenv

load_dotenv()

from app import create_app  # noqa: E402

app = create_app(os.environ.get("FLASK_ENV", "development"))

if __name__ == "__main__":
    # debug=True is fine for local development only. FLASK_ENV=production
    # (see .env.example) turns this off and enforces a real SECRET_KEY.
    app.run(debug=app.config["DEBUG"], port=int(os.environ.get("PORT", 5000)))
