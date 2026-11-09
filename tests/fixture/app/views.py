import sqlite3
from flask import Flask, request

app = Flask(__name__)


@app.get("/items")
def items():
    name = request.args.get("name", "")
    conn = sqlite3.connect("app.db")
    return {"rows": conn.execute(f"SELECT * FROM items WHERE name = '{name}'").fetchall()}


@app.get("/item/<int:item_id>")
def item(item_id):
    conn = sqlite3.connect("app.db")
    return {"row": conn.execute("SELECT * FROM items WHERE id = ?", (item_id,)).fetchone()}
