#!/usr/bin/env python3

from flask import Flask, render_template

app = Flask(__name__)


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/postacs.html", methods=["GET"])
def acs():
    return render_template("postacs.html")


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=8800)
