import os
import base64
import time
import json
import requests
import datetime
from typing import Any


from flask import Flask, request, render_template
from dotenv import load_dotenv
import plotly.graph_objects as go
import plotly.utils


load_dotenv()


app = Flask(__name__)


VT_API_KEY = os.getenv("VT_API_KEY")
if not VT_API_KEY:
    raise RuntimeError("VT_API_KEY missing")


HEADERS = {"x-apikey": VT_API_KEY}



def url_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")



def submit_url(url: str) -> None:
    requests.post(
        "https://www.virustotal.com/api/v3/urls",
        headers={**HEADERS, "content-type": "application/x-www-form-urlencoded"},
        data={"url": url},
        timeout=30,
    )



def get_report(url: str, retries: int = 6) -> dict[str, Any]:
    uid = url_id(url)
    for _ in range(retries):
        r = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{uid}",
            headers=HEADERS,
            timeout=30,
        )
        if r.status_code == 200:
            return r.json()
        if r.status_code == 404:
            submit_url(url)
        time.sleep(4)
    r.raise_for_status()



def get_color(value: float, max_val: float = 100, good_threshold: float = 70) -> str:
    normalized = (value / max_val) * 100
    if normalized >= good_threshold:
        return "green"
    if normalized >= 30:
        return "orange"
    return "red"



def calc_trust_score(stats: dict[str, int], votes: dict[str, int], reputation: int) -> int:
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless_votes = votes.get("harmless", 0)
    malicious_votes = votes.get("malicious", 0)


    score = 100
    score -= malicious * 10
    score -= suspicious * 5
    score -= malicious_votes
    score += harmless_votes
    score -= (100-reputation)//2


    return max(0, min(100, score))



def build_visuals(vt: dict[str, Any]) -> dict[str, Any]:
    a = vt["data"]["attributes"]


    stats = a.get("last_analysis_stats", {})
    votes = a.get("total_votes", {})
    reputation = a.get("reputation", 0)
    results = a.get("last_analysis_results", {})
    tags = a.get("tags", [])
    threat_names = a.get("threat_names", [])


    engines_by_cat = {}
    for data in results.values():
        cat = data.get("category", "unknown")
        engines_by_cat[cat] = engines_by_cat.get(cat, 0) + 1


    trust_score = calc_trust_score(stats, votes, reputation)


    return {
        "analysis": stats,
        "votes": votes,
        "reputation": reputation,
        "trust_score": trust_score,
        "engines_by_cat": engines_by_cat,
        "engines_total": len(results),
        "http": {
            "code": a.get("last_http_response_code", 0),
            "size": a.get("last_http_response_content_length", 0),
        },
        "timeline": {
            "first": datetime.datetime.fromtimestamp(a.get("first_submission_date"))
            if a.get("first_submission_date")
            else None,
            "last": datetime.datetime.fromtimestamp(a.get("last_submission_date"))
            if a.get("last_submission_date")
            else None,
            "analysis": datetime.datetime.fromtimestamp(a.get("last_analysis_date"))
            if a.get("last_analysis_date")
            else None,
            "mods": a.get("last_modification_date"),
            "times_submitted": a.get("times_submitted", 0),
        },
        "meta": {
            "final_url": a.get("last_final_url") or a.get("url"),
            "tld": a.get("tld"),
            "tags": tags,
            "threat_names": threat_names,
            "categories": list(a.get("categories", {}).values()),
        },
    }



def build_radar_metrics(visuals: dict[str, Any]) -> tuple[list[float], list[str]]:
    stats = visuals["analysis"]
    reputation = min(100, visuals["reputation"] * (-1))
    

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    total_sum = malicious + suspicious + harmless
    max_rep = 100
    inv_reputation = max_rep - visuals["trust_score"]

    r = [round((malicious/total_sum)*100),round((suspicious/total_sum)*100), inv_reputation,  reputation]
    theta = ["Malicious", "Suspicious", "Low Trust", "Low Reputation"]
    return r, theta



def build_figures_py(visuals: dict[str, Any]) -> dict[str, str]:
    stats = visuals["analysis"]
    votes = visuals["votes"]
    trust_score = visuals["trust_score"]
    http_code = visuals["http"]["code"]
    reputation = visuals["reputation"]


    donut_labels = ["harmless", "malicious", "suspicious", "undetected"]
    donut_values = [stats.get(k, 0) for k in donut_labels]
    colors = ["green", "red", "orange", "gray"]
    fig_donut = go.Figure(
        data=[
            go.Pie(
                labels=donut_labels,
                values=donut_values,
                hole=0.6,
                marker=dict(colors=colors),
            )
        ]
    )
    fig_donut.update_layout(margin=dict(l=20, r=20, t=20, b=20))


    radar_r, radar_theta = build_radar_metrics(visuals)
    fig_radar = go.Figure()
    fig_radar.add_trace(
        go.Scatterpolar(
            r=radar_r,
            theta=radar_theta,
            fill="tonext",
            line_color="darkred",
            fillcolor="rgba(255,0,0,0.3)"
        )
    )
    fig_radar.update_layout(
        polar=dict(radialaxis=dict(visible=True, range=[0, 100])),
        showlegend=False,
        margin=dict(l=20, r=20, t=20, b=20),
    )


    trust_color = get_color(trust_score)
    fig_trust = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=reputation,
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": trust_color},
                "steps": [
                    {"range": [0, 30], "color": "red"},
                    {"range": [30, 70], "color": "yellow"},
                    {"range": [70, 100], "color": "green"},
                ],
            },
        )
    )
    fig_trust.update_layout(margin=dict(l=20, r=20, t=20, b=20))


    http_color = (
        "green"
        if 200 <= http_code < 400
        else "red"
        if http_code >= 400
        else "orange"
    )
    fig_http = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=http_code,
            gauge={
                "axis": {"range": [0, 600]},
                "bar": {"color": http_color},
                "steps": [
                    {"range": [0, 199], "color": "red"},
                    {"range": [200, 299], "color": "green"},
                    {"range": [300, 399], "color": "orange"},
                    {"range": [400, 600], "color": "red"},
                ],
            },
        )
    )
    fig_http.update_layout(margin=dict(l=20, r=20, t=20, b=20))


    vote_labels = list(votes.keys())
    vote_values = list(votes.values())
    vote_colors = ["green" if "harmless" in label else "red" for label in vote_labels]
    fig_votes = go.Figure(
        data=[
            go.Pie(
                labels=vote_labels,
                values=vote_values,
                hole=0.4,
                marker=dict(colors=vote_colors),
            )
        ]
    )
    fig_votes.update_layout(margin=dict(l=20, r=20, t=20, b=20))


    rep_color = get_color(reputation, max_val=20, good_threshold=10)
    fig_reputation = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=reputation,
            gauge={
                "axis": {"range": [-20, 20]},
                "bar": {"color": rep_color},
                "steps": [
                    {"range": [-20, 0], "color": "red"},
                    {"range": [0, 10], "color": "orange"},
                    {"range": [10, 20], "color": "green"},
                ],
            },
        )
    )
    fig_reputation.update_layout(margin=dict(l=20, r=20, t=20, b=20))


    return {
        "donut": json.dumps(fig_donut, cls=plotly.utils.PlotlyJSONEncoder),
        "radar": json.dumps(fig_radar, cls=plotly.utils.PlotlyJSONEncoder),
        "trust": json.dumps(fig_trust, cls=plotly.utils.PlotlyJSONEncoder),
        "http": json.dumps(fig_http, cls=plotly.utils.PlotlyJSONEncoder),
        "votes": json.dumps(fig_votes, cls=plotly.utils.PlotlyJSONEncoder),
        "reputation": json.dumps(fig_reputation, cls=plotly.utils.PlotlyJSONEncoder),
    }



@app.route("/", methods=["GET", "POST"])
def scanner():
    error = None
    visuals = None
    result = None
    url = None
    figs = None


    if request.method == "POST":
        url = request.form.get("url")
        try:
            vt = get_report(url)
            visuals = build_visuals(vt)
            figs = build_figures_py(visuals)
            result = json.dumps(vt, indent=2, ensure_ascii=False)
        except Exception as e:
            error = str(e)


    return render_template(
        "scanner.html",
        visualizations=visuals,
        figures=figs,
        result=result,
        error=error,
        url=url,
    )



if __name__ == "__main__":
    app.run(debug=True)
