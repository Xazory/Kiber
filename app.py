"""
Учебная SOC-песочница по кибербезопасности
-----------------------------------------
Streamlit-приложение для безопасной отработки учебных сценариев в изолированной среде.

Запуск:
    pip install -r requirements.txt
    streamlit run app.py
"""

from __future__ import annotations

from datetime import datetime, timedelta
from io import BytesIO
from random import Random
from typing import Any, Dict, List

import pandas as pd
import plotly.express as px
import streamlit as st

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
except Exception:
    colors = None
    A4 = None
    ParagraphStyle = None
    getSampleStyleSheet = None
    mm = None
    SimpleDocTemplate = None
    Paragraph = None
    Spacer = None
    Table = None
    TableStyle = None


st.set_page_config(
    page_title="Учебная SOC-песочница",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown(
    """
    <style>
    .block-container {padding-top: 1.1rem; padding-bottom: 2rem;}
    .soft-card {
        border: 1px solid rgba(128,128,128,0.22);
        border-radius: 18px;
        padding: 16px 16px 10px 16px;
        background: rgba(255,255,255,0.03);
        margin-bottom: 12px;
    }
    .muted {opacity: 0.75;}
    .small {font-size: 0.92rem;}
    </style>
    """,
    unsafe_allow_html=True,
)

SEVERITIES = ["Info", "Low", "Medium", "High", "Critical"]
PROFILE_CHOICES = {
    "Веб-приложение": "web",
    "Сетевая подсистема": "network",
    "Почтовый шлюз": "mail",
}


SCENARIOS: List[Dict[str, Any]] = [
    {
        "id": "web-breach",
        "title": "Компрометация веб-приложения",
        "brief": "Аномалии на веб-слое похожи на перебор учётных данных, SQL-инъекцию и доступ к админ-панели.",
        "goals": [
            "Сопоставить цепочку событий от внешнего сканирования до подозрительного входа",
            "Найти источник аномальной активности",
            "Определить критический момент эскалации инцидента",
        ],
        "sources": ["WAF", "App Server", "Auth Service", "Database", "SIEM"],
    },
    {
        "id": "lateral-movement",
        "title": "Сетевая подсистема и боковое перемещение",
        "brief": "Внутренний узел начинает нестандартные соединения, DNS-запросы и попытки доступа к нескольким хостам.",
        "goals": [
            "Выявить первый заражённый узел",
            "Проследить lateral movement между сегментами",
            "Определить, какие алерты были сигналом к изоляции хоста",
        ],
        "sources": ["Firewall", "DNS", "NetFlow", "EDR", "SIEM"],
    },
    {
        "id": "mail-compromise",
        "title": "Почтовый шлюз и фишинговая кампания",
        "brief": "Ложные уведомления и вложения приводят к подозрительным входам, запуску макросов и пересылке писем.",
        "goals": [
            "Найти первичное письмо-триггер",
            "Понять, как пользовательский клик повлиял на последующие события",
            "Проверить, была ли утечка данных через почту",
        ],
        "sources": ["Mail Gateway", "Endpoint", "Identity Provider", "DLP", "SIEM"],
    },
    {
        "id": "hybrid-exfil",
        "title": "Гибридный сценарий: веб + почта + сеть",
        "brief": "Фишинг, веб-доступ и аномальный трафик наружу связаны в единую цепочку инцидента.",
        "goals": [
            "Построить полную временную линию инцидента",
            "Разделить сигналы по источникам и критичности",
            "Сформировать отчёт по итогам упражнения",
        ],
        "sources": ["Mail Gateway", "WAF", "Endpoint", "Firewall", "SIEM"],
    },
]


def init_state() -> None:
    defaults = {
        "selected_scenario": SCENARIOS[0]["id"],
        "selected_profile": "web",
        "events": [],
        "scenario_started_at": None,
        "progress": 0,
        "completed_steps": 0,
        "total_steps": 5,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def scenario_by_id(scenario_id: str) -> Dict[str, Any]:
    return next(s for s in SCENARIOS if s["id"] == scenario_id)


def severity_score(severity: str) -> int:
    return {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}.get(severity, 1)


def make_events(scenario: Dict[str, Any], profile: str) -> List[Dict[str, Any]]:
    seed = abs(hash((scenario["id"], profile))) % (2**32)
    rng = Random(seed)
    base_time = datetime.now().replace(microsecond=0) - timedelta(minutes=85)

    event_templates = {
        "web": [
            ("Info", "Внешний IP начал массовое сканирование путей приложения."),
            ("Low", "WAF зафиксировал необычные параметры запроса и высокий процент 4xx."),
            ("Medium", "Повторные попытки входа с разных учётных записей."),
            ("High", "Подозрительный POST-запрос совпал с шаблоном SQL-инъекции."),
            ("Critical", "Неавторизованный доступ к административному разделу."),
            ("High", "Создан новый токен с повышенными правами."),
            ("Medium", "Из БД выгружен объём данных выше нормы."),
            ("Critical", "SIEM обнаружил цепочку действий, ведущую к утечке данных."),
        ],
        "network": [
            ("Info", "На периметре отмечены исходящие соединения к редким адресам."),
            ("Low", "DNS-запросы содержат длинные и нетипичные поддомены."),
            ("Medium", "EDR сообщил о запуске неизвестного процесса."),
            ("High", "Внутренний хост инициировал соединения к нескольким сегментам."),
            ("Critical", "Подтверждено боковое перемещение между рабочими станциями."),
            ("High", "Обнаружены повторяющиеся попытки доступа к административным портам."),
            ("Medium", "Фиксируется подозрительный outbound-трафик."),
            ("Critical", "Операторы SOC рекомендуют изоляцию узла."),
        ],
        "mail": [
            ("Info", "Почтовый шлюз получил кампанию похожих писем от внешнего домена."),
            ("Low", "Тема письма похожа на корпоративное уведомление."),
            ("Medium", "Открыт вложенный файл с макросами."),
            ("High", "Endpoint отметил подозрительный запуск дочернего процесса."),
            ("Critical", "Зафиксирован вход в учётную запись после получения письма."),
            ("High", "Обнаружена массовая пересылка сообщений наружу."),
            ("Medium", "DLP заметил данные, похожие на служебные."),
            ("Critical", "Письмо-триггер связано с последующей компрометацией."),
        ],
    }

    templates = event_templates.get(profile, event_templates["web"])
    events: List[Dict[str, Any]] = []
    step_gap = rng.randint(6, 11)

    for idx, (severity, msg) in enumerate(templates, start=1):
        ts = base_time + timedelta(minutes=step_gap * idx + rng.randint(0, 2))
        source = rng.choice(scenario["sources"])
        if idx == 1:
            source = scenario["sources"][0]
        elif idx == len(templates):
            source = scenario["sources"][-1]
        events.append(
            {
                "timestamp": ts,
                "time": ts.strftime("%H:%M:%S"),
                "severity": severity,
                "source": source,
                "message": msg,
                "stage": f"Шаг {idx}",
                "details": f"Сценарий: {scenario['title']}. Профиль атаки: {profile}.",
                "score": severity_score(severity),
            }
        )

    noise_pool = [
        ("Info", "Обычный heartbeat от агента мониторинга."),
        ("Low", "Необычная частота DNS-запросов без подтверждённого вредоносного индикатора."),
        ("Info", "Успешная авторизация сотрудника из внутренней сети."),
        ("Low", "Кратковременный всплеск ошибок на сервисе без деградации."),
    ]
    for _ in range(3):
        severity, msg = rng.choice(noise_pool)
        ts = base_time + timedelta(minutes=rng.randint(1, step_gap * len(templates) + 5))
        events.append(
            {
                "timestamp": ts,
                "time": ts.strftime("%H:%M:%S"),
                "severity": severity,
                "source": rng.choice(scenario["sources"]),
                "message": msg,
                "stage": "Фоновое событие",
                "details": f"Сценарий: {scenario['title']}. Это шум для тренировки фильтрации событий.",
                "score": severity_score(severity),
            }
        )

    events.sort(key=lambda e: e["timestamp"])
    return events


def build_dataframe(events: List[Dict[str, Any]]) -> pd.DataFrame:
    if not events:
        return pd.DataFrame(
            columns=["timestamp", "time", "severity", "source", "message", "stage", "details", "score"]
        )
    df = pd.DataFrame(events)
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    return df


def apply_filters(df: pd.DataFrame, severities: List[str], sources: List[str]) -> pd.DataFrame:
    if df.empty:
        return df
    result = df.copy()
    if severities:
        result = result[result["severity"].isin(severities)]
    if sources:
        result = result[result["source"].isin(sources)]
    return result.sort_values("timestamp").reset_index(drop=True)


def progress_from_events(events: List[Dict[str, Any]]) -> tuple[int, int, int]:
    if not events:
        return 0, 0, 5
    total_steps = max(5, len([e for e in events if e["stage"] != "Фоновое событие"]))
    completed = min(total_steps, len([e for e in events if severity_score(e["severity"]) >= 3]))
    progress = int((completed / total_steps) * 100)
    return completed, progress, total_steps


def metrics_for_df(df: pd.DataFrame) -> Dict[str, Any]:
    if df.empty:
        return {"events": 0, "critical": 0, "sources": 0, "first": None, "last": None, "duration_min": 0}
    first = df["timestamp"].min()
    last = df["timestamp"].max()
    duration = max(0, int((last - first).total_seconds() // 60))
    return {
        "events": int(len(df)),
        "critical": int((df["severity"] == "Critical").sum()),
        "sources": int(df["source"].nunique()),
        "first": first,
        "last": last,
        "duration_min": duration,
    }


def export_csv(df: pd.DataFrame) -> bytes:
    out = BytesIO()
    export_df = df.copy()
    if not export_df.empty:
        export_df["timestamp"] = export_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    export_df.to_csv(out, index=False)
    return out.getvalue()


def export_pdf(df: pd.DataFrame, scenario: Dict[str, Any], profile_label: str) -> bytes:
    if SimpleDocTemplate is None:
        # fallback: plain text bytes
        lines = [
            f"SOC report: {scenario['title']}",
            f"Profile: {profile_label}",
            f"Events: {len(df)}",
        ]
        return "\n".join(lines).encode("utf-8")

    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=14 * mm,
        leftMargin=14 * mm,
        topMargin=14 * mm,
        bottomMargin=14 * mm,
    )
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontSize=9, leading=11))

    metrics = metrics_for_df(df)
    story = [
        Paragraph("Учебная SOC-песочница — отчёт по упражнению", styles["Title"]),
        Spacer(1, 8),
        Paragraph(f"<b>Сценарий:</b> {scenario['title']}", styles["BodyText"]),
        Paragraph(f"<b>Профиль атаки:</b> {profile_label}", styles["BodyText"]),
        Paragraph(f"<b>Событий:</b> {metrics['events']} | <b>Критических:</b> {metrics['critical']}", styles["BodyText"]),
        Paragraph(
            f"<b>Окно событий:</b> {metrics['first']} — {metrics['last']} | <b>Длительность:</b> {metrics['duration_min']} мин.",
            styles["BodyText"],
        ),
        Spacer(1, 8),
        Paragraph("Ключевые события", styles["Heading2"]),
    ]

    table_data = [["Время", "Критичность", "Источник", "Событие"]]
    for _, row in df.head(12).iterrows():
        table_data.append([row["timestamp"].strftime("%H:%M:%S"), row["severity"], row["source"], row["message"]])

    table = Table(table_data, colWidths=[22 * mm, 24 * mm, 38 * mm, 92 * mm])
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8.5),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f3f4f6")]),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 8))
    story.append(Paragraph("Цели упражнения", styles["Heading2"]))
    for goal in scenario["goals"]:
        story.append(Paragraph(f"• {goal}", styles["Small"]))

    doc.build(story)
    return buffer.getvalue()


def main() -> None:
    init_state()

    scenario_obj = scenario_by_id(st.session_state.selected_scenario)
    profile_label = next(k for k, v in PROFILE_CHOICES.items() if v == st.session_state.selected_profile)

    if not st.session_state.events:
        st.session_state.events = make_events(scenario_obj, st.session_state.selected_profile)
        st.session_state.completed_steps, st.session_state.progress, st.session_state.total_steps = progress_from_events(
            st.session_state.events
        )
        st.session_state.scenario_started_at = datetime.now().replace(microsecond=0)

    with st.sidebar:
        st.title("🛡️ SOC-песочница")
        st.caption("Изолированный стенд для отработки сценариев, визуализации инцидентов и сброса состояния.")

        scenario_titles = {s["title"]: s["id"] for s in SCENARIOS}
        selected_title = st.selectbox(
            "Сценарий",
            options=list(scenario_titles.keys()),
            index=list(scenario_titles.keys()).index(scenario_obj["title"]),
        )
        selected_scenario_id = scenario_titles[selected_title]

        profile_label_input = st.radio(
            "Профиль атак",
            options=list(PROFILE_CHOICES.keys()),
            index=list(PROFILE_CHOICES.values()).index(st.session_state.selected_profile),
        )
        selected_profile = PROFILE_CHOICES[profile_label_input]

        col_a, col_b = st.columns(2)
        with col_a:
            start_clicked = st.button("▶ Запустить", use_container_width=True)
        with col_b:
            reset_clicked = st.button("↺ Сброс", use_container_width=True)

        st.divider()
        st.subheader("Фильтры событий")
        severity_filter = st.multiselect(
            "Критичность",
            options=SEVERITIES,
            default=["Medium", "High", "Critical"],
        )

        current_df = build_dataframe(st.session_state.events)
        sources_available = sorted(current_df["source"].unique().tolist()) if not current_df.empty else []
        source_filter = st.multiselect(
            "Источник",
            options=sources_available,
            default=sources_available,
        )

        st.divider()
        st.caption("Отчёт можно скачать после запуска сценария.")

    state_changed = False
    if selected_scenario_id != st.session_state.selected_scenario:
        st.session_state.selected_scenario = selected_scenario_id
        state_changed = True
    if selected_profile != st.session_state.selected_profile:
        st.session_state.selected_profile = selected_profile
        state_changed = True

    if state_changed:
        scenario_obj = scenario_by_id(st.session_state.selected_scenario)
        st.session_state.events = make_events(scenario_obj, st.session_state.selected_profile)
        st.session_state.completed_steps, st.session_state.progress, st.session_state.total_steps = progress_from_events(
            st.session_state.events
        )
        st.session_state.scenario_started_at = datetime.now().replace(microsecond=0)

    if start_clicked:
        scenario_obj = scenario_by_id(st.session_state.selected_scenario)
        st.session_state.events = make_events(scenario_obj, st.session_state.selected_profile)
        st.session_state.completed_steps, st.session_state.progress, st.session_state.total_steps = progress_from_events(
            st.session_state.events
        )
        st.session_state.scenario_started_at = datetime.now().replace(microsecond=0)
        st.toast("Сценарий запущен", icon="✅")

    if reset_clicked:
        st.session_state.events = []
        st.session_state.progress = 0
        st.session_state.completed_steps = 0
        st.session_state.total_steps = 5
        st.session_state.scenario_started_at = None
        st.rerun()

    scenario_obj = scenario_by_id(st.session_state.selected_scenario)
    all_df = build_dataframe(st.session_state.events)
    filtered_df = apply_filters(all_df, severity_filter, source_filter)
    metrics = metrics_for_df(filtered_df)

    st.title("Учебная SOC-песочница по кибербезопасности")
    st.write("Безопасный стенд для тренировки анализа событий, расследования инцидентов и формирования отчёта.")

    st.markdown('<div class="soft-card">', unsafe_allow_html=True)
    left, right = st.columns([1.4, 1])
    with left:
        st.subheader(scenario_obj["title"])
        st.write(scenario_obj["brief"])
        st.markdown("**Цели упражнения**")
        for goal in scenario_obj["goals"]:
            st.markdown(f"- {goal}")
    with right:
        st.metric("Прогресс сценария", f"{st.session_state.progress}%")
        st.progress(st.session_state.progress / 100 if st.session_state.progress else 0)
        st.caption(f"Выполнено шагов: {st.session_state.completed_steps} из {st.session_state.total_steps}")
        st.caption(f"Профиль атак: {profile_label}")
    st.markdown("</div>", unsafe_allow_html=True)

    k1, k2, k3, k4 = st.columns(4)
    k1.metric("Событий в выборке", metrics["events"])
    k2.metric("Критических", metrics["critical"])
    k3.metric("Источников", metrics["sources"])
    k4.metric("Окно времени", f"{metrics['duration_min']} мин")

    if not filtered_df.empty:
        chart_df = filtered_df.copy()
        chart_df["sev_rank"] = chart_df["severity"].map(severity_score)
        fig = px.scatter(
            chart_df,
            x="timestamp",
            y="sev_rank",
            color="severity",
            hover_data={"source": True, "message": True, "stage": True, "sev_rank": False},
            title="Таймлайн событий безопасности",
            labels={"timestamp": "Время", "sev_rank": "Критичность"},
            height=420,
        )
        fig.update_yaxes(
            tickmode="array",
            tickvals=[1, 2, 3, 4, 5],
            ticktext=["Info", "Low", "Medium", "High", "Critical"],
        )
        fig.update_traces(marker=dict(size=12, line=dict(width=1, color="white")))
        fig.update_layout(legend_title_text="Критичность", margin=dict(l=10, r=10, t=50, b=10))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("По выбранным фильтрам событий нет.")

    left_col, right_col = st.columns([1.35, 1])
    with left_col:
        st.subheader("Лента событий")
        table_df = filtered_df.copy()
        if not table_df.empty:
            table_df = table_df[["timestamp", "severity", "source", "stage", "message"]].rename(
                columns={
                    "timestamp": "Время",
                    "severity": "Критичность",
                    "source": "Источник",
                    "stage": "Этап",
                    "message": "Событие",
                }
            )
            table_df["Время"] = table_df["Время"].dt.strftime("%H:%M:%S")
            st.dataframe(table_df, use_container_width=True, hide_index=True)
        else:
            st.write("Нет строк для отображения.")

    with right_col:
        st.subheader("Детали расследования")
        if not filtered_df.empty:
            top_event = filtered_df.sort_values(["score", "timestamp"], ascending=[False, True]).iloc[0]
            st.markdown(
                f"""
                <div class="soft-card">
                <b>Самый критичный сигнал</b><br>
                <span class="muted">{top_event['timestamp'].strftime('%H:%M:%S')} · {top_event['severity']} · {top_event['source']}</span><br><br>
                {top_event['message']}<br><br>
                <span class="small">{top_event['details']}</span>
                </div>
                """,
                unsafe_allow_html=True,
            )
            summary = (
                filtered_df.groupby(["severity", "source"]).size().reset_index(name="count").sort_values(
                    ["count", "severity"], ascending=[False, False]
                )
            )
            st.caption("Распределение событий по критичности и источникам")
            st.dataframe(summary.head(10), use_container_width=True, hide_index=True)
        else:
            st.info("Выберите другие фильтры, чтобы увидеть сводку по событиям.")

    st.subheader("Отчёт по упражнению")
    if not filtered_df.empty:
        csv_bytes = export_csv(filtered_df)
        pdf_bytes = export_pdf(filtered_df, scenario_obj, profile_label)

        c1, c2, c3 = st.columns([1, 1, 2])
        with c1:
            st.download_button(
                label="Скачать CSV",
                data=csv_bytes,
                file_name=f"soc_report_{scenario_obj['id']}.csv",
                mime="text/csv",
                use_container_width=True,
            )
        with c2:
            st.download_button(
                label="Скачать PDF",
                data=pdf_bytes,
                file_name=f"soc_report_{scenario_obj['id']}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        with c3:
            st.caption("В отчёт входят базовые метрики: количество событий, критические алерты, окно времени и таймлайн.")
    else:
        st.caption("Отчёт формируется по текущей выборке событий.")

    st.caption("Совет: меняйте профиль атак, запускайте сценарий повторно и сравнивайте, как меняется лента событий.")


if __name__ == "__main__":
    main()
