import os
import smtplib
from email.message import EmailMessage
import pandas as pd
import matplotlib.pyplot as plt
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image, Table, TableStyle
from datetime import datetime, timezone
import json
import asyncio
import uuid

from .config import SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS, SMTP_FROM, REPORT_PROMPT_PATH
from .opensearch_api import indexer_request
from .llm import _build_llm
from .dashboard_plan import _last_json_block

async def generate_report_kql_query(topic: str, index_pattern: str) -> dict:
    llm = _build_llm()
    
    sys_prompt_content = ""
    try:
        if REPORT_PROMPT_PATH and os.path.exists(REPORT_PROMPT_PATH):
            with open(REPORT_PROMPT_PATH, "r", encoding="utf-8") as f:
                sys_prompt_content = f.read()
    except Exception as e:
        print(f"Warning: Failed to read Report prompt from {REPORT_PROMPT_PATH}: {e}")
        sys_prompt_content = "You are an AI generating exactly one JSON object with parameters for a Wazuh/OpenSearch query to build a detailed PDF report."

    sys_prompt = sys_prompt_content
    user = (
        f"Default Index pattern (you can override this): {index_pattern}\n"
        f"Topic: {topic}\n"
    )
    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user)
    raw = getattr(msg, "content", "") or ""
    try:
        plan = json.loads(_last_json_block(raw))
    except Exception:
        plan = {"index_pattern": index_pattern, "query": "", "time_from": "now-24h", "time_to": "now", "title": f"Report for {topic}", "visualizations": [
            {"type": "pie", "agg_field": "agent.name", "title": "Top Agents"},
            {"type": "bar", "agg_field": "rule.description", "title": "Top Rules Triggered"}
        ]}
    return plan

async def fetch_report_data(index_pattern: str, query: str, time_from: str, time_to: str, visualizations: list) -> dict:
    is_state = index_pattern.startswith("wazuh-states-")
    time_field = "@timestamp"
    
    aggs = {}
    for i, viz in enumerate(visualizations):
        field = viz.get("agg_field")
        if field:
            if viz.get("type") == "line":
                aggs[f"viz_{i}"] = {
                    "date_histogram": {
                        "field": time_field,
                        "calendar_interval": "1h"
                    }
                }
            else:
                aggs[f"viz_{i}"] = {
                    "terms": {"field": field, "size": 15}
                }

    body = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [],
                "filter": []
            }
        },
        "aggs": aggs
    }
    
    if not is_state:
        body["query"]["bool"]["filter"].append({"range": {time_field: {"gte": time_from, "lte": time_to}}})
        body["sort"] = [{time_field: {"order": "desc"}}]
    
    if query:
        body["query"]["bool"]["must"].append({
            "query_string": {"query": query}
        })
        
    status, result = await indexer_request("POST", f"/{index_pattern}/_search", params={"scroll": "1m"}, json_body=body)
    if status == 200:
        initial_data = json.loads(result)
        all_hits = list(initial_data.get("hits", {}).get("hits", []))
        scroll_id = initial_data.get("_scroll_id")
        
        while scroll_id:
            scroll_body = {
                "scroll": "1m",
                "scroll_id": scroll_id
            }
            s_status, scroll_result = await indexer_request("POST", "/_search/scroll", json_body=scroll_body)
            if s_status == 200:
                scroll_data = json.loads(scroll_result)
                new_hits = scroll_data.get("hits", {}).get("hits", [])
                if not new_hits:
                    break
                all_hits.extend(new_hits)
                scroll_id = scroll_data.get("_scroll_id")
            else:
                break
                
        initial_data["hits"]["hits"] = all_hits
        if isinstance(initial_data["hits"].get("total"), dict):
            initial_data["hits"]["total"]["value"] = len(all_hits)
        else:
            initial_data["hits"]["total"] = len(all_hits)
            
        if scroll_id:
            try:
                await indexer_request("DELETE", f"/_search/scroll/{scroll_id}")
            except Exception:
                pass
                
        return initial_data
        
    return {}

def create_chart_image(data: dict, agg_name: str, viz_config: dict) -> str:
    buckets = data.get("aggregations", {}).get(agg_name, {}).get("buckets", [])
    if not buckets:
        return None
        
    df = pd.DataFrame(buckets)
    if df.empty:
        return None
        
    ctype = viz_config.get("type", "bar")
    title = viz_config.get("title", "Chart")
    
    # White / #0fcaf0 aesthetic
    plt.style.use('default')
    fig, ax = plt.subplots(figsize=(7, 4.5))
    fig.patch.set_facecolor('#ffffff')
    ax.set_facecolor('#ffffff')
    
    # Theme colors
    cyan = '#2a85ff'
    magenta = '#333333'
    
    def truncate_label(label, max_len=25):
        s = str(label)
        return s[:max_len] + '...' if len(s) > max_len else s
        
    key_col = 'key_as_string' if 'key_as_string' in df.columns else 'key'
    if ctype != "line":
        df[key_col] = df[key_col].apply(truncate_label)
    
    if ctype == "pie":
        df = df.sort_values(by='doc_count', ascending=False)
        colors_list = plt.cm.plasma(pd.np.linspace(0.1, 0.9, len(df))) if hasattr(pd, 'np') else plt.cm.tab20([i/max(1, len(df)-1) for i in range(len(df))])
        ax.pie(df['doc_count'], labels=df[key_col], autopct='%1.1f%%', startangle=140, colors=colors_list, textprops={'fontsize': 8, 'color': 'black'})
        ax.set_title(title, pad=20, fontsize=12, fontweight='bold', color='black')
    elif ctype == "line":
        x_data = pd.to_datetime(df[key_col]) if 'key_as_string' in df.columns else df[key_col]
        ax.plot(x_data, df['doc_count'], marker='o', linestyle='-', color=cyan, linewidth=2, markersize=6)
        ax.set_title(title, pad=15, fontsize=12, fontweight='bold', color='black')
        ax.set_xlabel('Time', fontsize=10, color='black')
        ax.set_ylabel('Count', fontsize=10, color='black')
        ax.tick_params(axis='x', rotation=45, labelsize=8, colors='black')
        ax.tick_params(axis='y', labelsize=8, colors='black')
        ax.grid(True, linestyle=':', alpha=0.3, color='grey')
    else: 
        df = df.sort_values(by='doc_count', ascending=True)
        bars = ax.barh(df[key_col], df['doc_count'], color=cyan, edgecolor='#ffffff', linewidth=1)
        ax.set_xlabel('Count', fontsize=10, color='black')
        ax.set_title(title, pad=15, fontsize=12, fontweight='bold', color='black')
        ax.tick_params(axis='y', labelsize=8, colors='black')
        ax.tick_params(axis='x', labelsize=8, colors='black')
        ax.grid(axis='x', linestyle=':', alpha=0.3, color='grey')
        for bar in bars:
            width = bar.get_width()
            ax.text(width, bar.get_y() + bar.get_height()/2, f' {int(width):,}', ha='left', va='center', fontsize=8, color=cyan, fontweight='bold')
            
    # Add neon border
    for spine in ax.spines.values():
        spine.set_edgecolor(cyan)
        spine.set_linewidth(1.5)
            
    plt.tight_layout()
    
    img_path = f"/tmp/chart_{agg_name}_{uuid.uuid4().hex[:8]}.png"
    plt.savefig(img_path, format='png', dpi=120, bbox_inches='tight', facecolor=fig.get_facecolor(), transparent=False)
    plt.close()
    return img_path

def build_pdf(filepath: str, title: str, data: dict, chart_paths: list, summary: str = ""):
    styles = getSampleStyleSheet()
    
    # Custom vibrant styles
    title_style = ParagraphStyle(
        'FuturisticTitle',
        parent=styles['Title'],
        textColor=colors.HexColor('#000000'),
        fontSize=24,
        fontName='Helvetica-Bold',
        spaceAfter=30
    )
    normal_style = ParagraphStyle(
        'FuturisticNormal',
        parent=styles['Normal'],
        textColor=colors.HexColor('#000000'),
        fontSize=10,
        fontName='Helvetica'
    )
    heading_style = ParagraphStyle(
        'FuturisticHeading',
        parent=styles['Heading2'],
        textColor=colors.HexColor('#000000'),
        fontName='Helvetica-Bold',
        spaceAfter=10
    )
    
    # Custom page background
    def add_background(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(colors.HexColor('#ffffff'))
        canvas.rect(0, 0, letter[0], letter[1], fill=1)
        # Decorative border
        canvas.setStrokeColor(colors.HexColor('#0fcaf0'))
        canvas.setLineWidth(2)
        canvas.rect(20, 20, letter[0]-40, letter[1]-40)
        canvas.restoreState()

    doc = SimpleDocTemplate(filepath, pagesize=letter, rightMargin=40, leftMargin=40, topMargin=40, bottomMargin=40)
    elements = []
    
    # Title & Timestamp
    elements.append(Paragraph(title.upper(), title_style))
    elements.append(Paragraph(f"<b>Generated:</b> <font color='#2a85ff'>{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}</font>", normal_style))
    elements.append(Spacer(1, 10))
    
    if summary:
        elements.append(Paragraph("<b>Executive Summary:</b>", heading_style))
        elements.append(Paragraph(summary, normal_style))
        elements.append(Spacer(1, 15))
    
    total_hits = data.get("hits", {}).get("total", {}).get("value", 0)
    elements.append(Spacer(1, 5))
    elements.append(Paragraph(f"<b>Total Events Found:</b> <font color='#333333'>{total_hits}</font>", normal_style))
    elements.append(Spacer(1, 20))
    
    # Charts
    for cp in chart_paths:
        if cp and os.path.exists(cp):
            elements.append(Image(cp, width=400, height=260))
            elements.append(Spacer(1, 20))
            
    # Data Table (Recent 10 events)
    hits = data.get("hits", {}).get("hits", [])
    if hits:
        elements.append(Paragraph("<b>Detailed Events List:</b>", heading_style))
        elements.append(Spacer(1, 10))
        
        is_vuln = "vulnerability" in hits[0].get("_source", {})
        if is_vuln:
            table_data = [["Time/Date", "Agent", "CVE ID", "Severity", "Description"]]
        else:
            table_data = [["Time/Date", "Agent", "Detail", "Severity"]]
            
        desc_style = ParagraphStyle(name='TableDesc', parent=styles['Normal'], fontSize=7, leading=8)

        for h in hits:
            src = h.get("_source", {})
            if is_vuln:
                ts = src.get("vulnerability", {}).get("detected_at", src.get("@timestamp", ""))
                agent = src.get("agent", {}).get("name", "Unknown")
                cve = src.get("vulnerability", {}).get("id", src.get("vulnerability", {}).get("cve", "Unknown"))
                level = str(src.get("vulnerability", {}).get("severity", ""))
                desc = str(src.get("vulnerability", {}).get("description", "")).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
                table_data.append([str(ts)[:19], agent, cve, level, Paragraph(desc, desc_style)])
            else:
                ts = src.get("@timestamp", src.get("vulnerability", {}).get("detected_at", ""))
                agent = src.get("agent", {}).get("name", "Unknown")
                rule_desc = src.get("rule", {}).get("description", "Unknown")
                level = str(src.get("rule", {}).get("level", ""))
                table_data.append([str(ts)[:19], agent, rule_desc, level])
            
        cols = [70, 70, 70, 45, 255] if is_vuln else [100, 80, 280, 50]
        t = Table(table_data, colWidths=cols)
        t.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#2a85ff')),
            ('TEXTCOLOR', (0,0), (-1,0), colors.HexColor('#ffffff')),
            ('ALIGN', (0,0), (-1,-1), 'LEFT'),
            ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
            ('FONTSIZE', (0,0), (-1,-1), 8),
            ('BOTTOMPADDING', (0,0), (-1,0), 6),
            ('BACKGROUND', (0,1), (-1,-1), colors.HexColor('#f8f9fa')),
            ('TEXTCOLOR', (0,1), (-1,-1), colors.HexColor('#333333')),
            ('GRID', (0,0), (-1,-1), 1, colors.HexColor('#2a85ff'))
        ]))
        elements.append(t)
        
    doc.build(elements, onFirstPage=add_background, onLaterPages=add_background)

async def generate_executive_summary(topic: str, data: dict, plan: dict) -> str:
    llm = _build_llm()
    total = data.get("hits", {}).get("total", {}).get("value", 0)
    top_items = []
    
    for i, viz in enumerate(plan.get("visualizations", [])):
        buckets = data.get("aggregations", {}).get(f"viz_{i}", {}).get("buckets", [])[:3]
        if buckets:
            items = ", ".join([f"{b['key']} ({b['doc_count']})" for b in buckets])
            top_items.append(f"Top {viz.get('title')}: {items}")

    sys_prompt = "You are a cybersecurity analyst. Write a concise, 2-to-3 sentence executive summary for an email to a manager based on the provided stats. Do not include introductory greetings or sign-offs, just the raw paragraph summary."
    user_prompt = f"Topic: {topic}\nTotal Events: {total}\nKey Findings:\n" + "\n".join(top_items)
    
    msg = await asyncio.to_thread(llm.invoke, sys_prompt + "\n" + user_prompt)
    return getattr(msg, "content", "") or f"A report concerning {topic} with {total} total events."

async def generate_pdf_report(topic: str, index_pattern: str, output_path: str) -> dict:
    plan = await generate_report_kql_query(topic, index_pattern)
    
    # Allow the LLM to override the index pattern based on the topic (e.g. for vulnerabilities)
    final_index = plan.get("index_pattern", index_pattern)
    
    viz_list = plan.get("visualizations", [])
    data = await fetch_report_data(final_index, plan.get("query", ""), plan.get("time_from", "now-24h"), plan.get("time_to", "now"), viz_list)
    
    chart_paths = []
    for i, viz in enumerate(viz_list):
        if viz.get("type") == "table":
            continue # Data tables handled generically at the end for now
        c_path = create_chart_image(data, f"viz_{i}", viz)
        if c_path: chart_paths.append(c_path)
        
    exec_summary = await generate_executive_summary(topic, data, plan)
        
    build_pdf(output_path, plan.get("title", "Wazuh Security Report"), data, chart_paths, summary=exec_summary)
    
    # Cleanup temp charts
    for cp in chart_paths:
        if cp and os.path.exists(cp):
            try: os.remove(cp)
            except: pass
            
    return {"pdf_path": output_path, "total_events": data.get("hits", {}).get("total", {}).get("value", 0), "title": plan.get("title"), "summary": exec_summary}

async def send_report_email(pdf_path: str, recipient_email: str, title: str, summary: str = "") -> bool:
    msg = EmailMessage()
    msg["Subject"] = f"Wazuh Report: {title}"
    msg["From"] = SMTP_FROM
    msg["To"] = recipient_email
    
    body = f"Hi,\n\nPlease find the attached {title} generated by the Wazuh AI Analyst.\n\nExecutive Summary:\n{summary}\n\nRegards,\nWazuh AI"
    msg.set_content(body)
    
    with open(pdf_path, 'rb') as f:
        pdf_data = f.read()
        
    msg.add_attachment(pdf_data, maintype='application', subtype='pdf', filename=os.path.basename(pdf_path))
    
    try:
        await asyncio.to_thread(_send_email_sync, msg)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def _send_email_sync(msg: EmailMessage):
    if SMTP_USER and SMTP_PASS:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
    else:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
            server.send_message(msg)
