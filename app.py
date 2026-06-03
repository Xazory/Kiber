"""
Учебная SOC-песочница по кибербезопасности
-----------------------------------------
Базовая улучшенная версия Streamlit-приложения для учебного анализа инцидентов.

Что умеет:
- запуск учебного сценария из списка
- просмотр событий безопасности по таймлайну
- фильтрация по критичности и источнику
- сброс стенда до чистого состояния
- выбор профиля атак: веб-приложение / сетевая подсистема / почтовый шлюз
- генерация отчёта PDF с русским текстом без «квадратов» при наличии Unicode-шрифта
- выгрузка отчёта PDF и CSV
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from random import Random
from typing import Any, Dict, List, Optional, Sequence

import pandas as pd
import plotly.express as px
import streamlit as st

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


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
SEVERITY_RANK = {"Info": 1, "Low": 2, "Medium": 3, "High": 4, "Critical": 5}
PROFILE_CHOICES = {
    "Веб-приложение": "web",
    "Сетевая подсистема": "network",
    "Почтовый шлюз": "mail",
}


@dataclass(frozen=True)
class Scenario:
    id: str
    title: str
    brief: str
    goals: List[str]
    sources: List[str]


SCENARIOS: List[Scenario] = [
    Scenario(
        id="web-breach",
        title="Компрометация веб-приложения",
        brief="На веб-слое видны признаки сканирования, перебора учетных данных, SQL-инъекции и доступа к админ-панели.",
        goals=[
            "Сопоставить цепочку событий от внешнего сканирования до подозрительного входа",
            "Найти источник аномальной активности",
            "Определить критический момент эскалации инцидента",
        ],
        sources=["WAF", "App Server", "Auth Service", "Database", "SIEM"],
    ),
    Scenario(
        id="lateral-movement",
        title="Сетевая подсистема и боковое перемещение",
        brief="Внутренний узел инициирует нетипичные DNS-запросы, соединения между сегментами и подозрительный трафик наружу.",
        goals=[
            "Выявить первый заражённый узел",
            "Проследить lateral movement между сегментами",
            "Определить сигнал к изоляции хоста",
        ],
        sources=["Firewall", "DNS", "NetFlow", "EDR", "SIEM"],
    ),
    Scenario(
        id="mail-compromise",
        title="Почтовый шлюз и фишинговая кампания",
        brief="Фишинговые письма приводят к открытию вложения, запуску макроса и компрометации учетной записи.",
        goals=[
            "Найти первичное письмо-триггер",
            "Понять влияние пользовательского клика на инцидент",
            "Проверить возможную утечку данных через почту",
        ],
        sources=["Mail Gateway", "Endpoint", "Identity Provider", "DLP", "SIEM"],
    ),
    Scenario(
        id="hybrid-exfil",
        title="Гибридный сценарий: веб + почта + сеть",
        brief="Фишинг, веб-доступ и аномальный сетевой трафик связаны в единую цепочку инцидента.",
        goals=[
            "Построить полную временную линию инцидента",
            "Разделить сигналы по источникам и критичности",
            "Сформировать отчёт по итогам упражнения",
        ],
        sources=["Mail Gateway", "WAF", "Endpoint", "Firewall", "SIEM"],
    ),
]


def init_state() -> None:
    defaults = {
        "selected_scenario": SCENARIOS[0].id,
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


init_state()


def scenario_by_id(scenario_id: str) -> Scenario:
    return next(s for s in SCENARIOS if s.id == scenario_id)


def severity_score(severity: str) -> int:
    return SEVERITY_RANK.get(severity, 1)


def find_unicode_font() -> Optional[str]:
    candidates = [
        Path("DejaVuSans.ttf"),
        Path("./DejaVuSans.ttf"),
        Path("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"),
        Path("/usr/local/share/fonts/DejaVuSans.ttf"),
        Path("C:/Windows/Fonts/DejaVuSans.ttf"),
        Path("C:/Windows/Fonts/arial.ttf"),
    ]
    for path in candidates:
        if path.exists():
            return str(path)
    return None


def register_pdf_font() -> Optional[str]:
    font_path = find_unicode_font()
    if not font_path:
        return None
    font_name = "SOCUnicode"
    try:
        pdfmetrics.registerFont(TTFont(font_name, font_path))
        return font_name
    except Exception:
        return None


def make_events(scenario: Scenario, profile: str) -> List[Dict[str, Any]]:
    seed = abs(hash((scenario.id, profile))) % (2**32)
    rng = Random(seed)

    profile_sources = {
        "web": ["WAF", "App Server", "Auth Service", "Database", "SIEM"],
        "network": ["Firewall", "DNS", "NetFlow", "EDR", "SIEM"],
        "mail": ["Mail Gateway", "Endpoint", "Identity Provider", "DLP", "SIEM"],
    }
    sources = profile_sources.get(profile, scenario.sources)

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
    base_time = datetime.now().replace(microsecond=0) - timedelta(minutes=84)
    step_gap = rng.randint(6, 11)

    events: List[Dict[str, Any]] = []
    for idx, (severity, message) in enumerate(templates, start=1):
        ts = base_time + timedelta(minutes=step_gap * idx + rng.randint(0, 2))
        source = rng.choice(sources)
        if idx == 1:
            source = sources[0]
        elif idx == len(templates):
            source = sources[-1]
        events.append(
            {
                "timestamp": ts,
                "time": ts.strftime("%H:%M:%S"),
                "severity": severity,
                "source": source,
                "message": message,
                "stage": f"Шаг {idx}",
                "details": f"Сценарий: {scenario.title}. Профиль атаки: {profile}.",
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
        severity, message = rng.choice(noise_pool)
        ts = base_time + timedelta(minutes=rng.randint(1, step_gap * len(templates) + 5))
        events.append(
            {
                "timestamp": ts,
                "time": ts.strftime("%H:%M:%S"),
                "severity": severity,
                "source": rng.choice(sources),
                "message": message,
                "stage": "Фоновое событие",
                "details": f"Сценарий: {scenario.title}. Это шум для тренировки фильтрации событий.",
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


def apply_filters(df: pd.DataFrame, severities: Sequence[str], sources: Sequence[str]) -> pd.DataFrame:
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
        return {
            "events": 0,
            "critical": 0,
            "high": 0,
            "sources": 0,
            "first": None,
            "last": None,
            "duration_min": 0,
        }
    first = df["timestamp"].min()
    last = df["timestamp"].max()
    duration = max(0, int((last - first).total_seconds() // 60))
    return {
        "events": int(len(df)),
        "critical": int((df["severity"] == "Critical").sum()),
        "high": int((df["severity"] == "High").sum()),
        "sources": int(df["source"].nunique()),
        "first": first,
        "last": last,
        "duration_min": duration,
    }


def top_sources_text(df: pd.DataFrame) -> str:
    if df.empty:
        return "Нет данных"
    counts = df["source"].value_counts().head(5)
    return "<br/>".join([f"{src}: {cnt} событий" for src, cnt in counts.items()])


def analysis_recommendations(df: pd.DataFrame) -> List[str]:
    recs: List[str] = []
    if df.empty:
        return ["Запустите сценарий, чтобы сформировать анализ."]
    if (df["severity"] == "Critical").any():
        recs.append("Проверить критические события на предмет первичного индикатора компрометации.")
    if df["source"].nunique() >= 4:
        recs.append("Сопоставить события между несколькими источниками, чтобы восстановить полную цепочку атаки.")
    if df[df["severity"].isin(["High", "Critical"])].shape[0] >= 3:
        recs.append("Изолировать затронутый узел или учетную запись и проверить соседние системы.")
    if not recs:
        recs.append("Продолжить сбор журналов и уточнить временное окно инцидента.")
    return recs


def export_csv(df: pd.DataFrame) -> bytes:
    out = BytesIO()
    export_df = df.copy()
    if not export_df.empty:
        export_df["timestamp"] = export_df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")
    export_df.to_csv(out, index=False)
    return out.getvalue()


def export_pdf(df: pd.DataFrame, scenario: Scenario, profile_label: str) -> bytes:
    font_name = register_pdf_font()
    if font_name is None:
        raise RuntimeError(
            "Не найден Unicode-шрифт для PDF. Положите DejaVuSans.ttf рядом с app.py или установите DejaVu Sans в систему."
        )

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
    styles.add(ParagraphStyle(name="Small", parent=styles["BodyText"], fontName=font_name, fontSize=9, leading=11))
    for name in styles.byName:
        try:
            styles[name].fontName = font_name
        except Exception:
            pass

    metrics = metrics_for_df(df)
    recs = analysis_recommendations(df)
    first_str = metrics["first"].strftime("%Y-%m-%d %H:%M:%S") if metrics["first"] is not None else "-"
    last_str = metrics["last"].strftime("%Y-%m-%d %H:%M:%S") if metrics["last"] is not None else "-"

    story: List[Any] = []
    story.append(Paragraph("Учебная SOC-песочница — отчёт по упражнению", styles["Title"]))
    story.append(Spacer(1, 6))
    story.append(Paragraph(f"<b>Сценарий:</b> {scenario.title}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Профиль атаки:</b> {profile_label}", styles["BodyText"]))
    story.append(Paragraph(f"<b>Дата формирования:</b> {datetime.now():%Y-%m-%d %H:%M:%S}", styles["BodyText"]))
    story.append(Spacer(1, 8))

    summary = (
        f"<b>Сводка</b><br/>"
        f"Всего событий: {metrics['events']}<br/>"
        f"Критических: {metrics['critical']}<br/>"
        f"Высоких: {metrics['high']}<br/>"
        f"Источник записей: {metrics['sources']}<br/>"
        f"Окно событий: {first_str} — {last_str}<br/>"
        f"Длительность окна: {metrics['duration_min']} мин"
    )
    story.append(Paragraph(summary, styles["BodyText"]))
    story.append(Spacer(1, 8))

    if not df.empty:
        story.append(Paragraph("Ключевые наблюдения", styles["Heading2"]))
        story.append(Paragraph(f"• {recs[0]}", styles["Small"]))
        if len(recs) > 1:
            for item in recs[1:]:
                story.append(Paragraph(f"• {item}", styles["Small"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Хронология событий", styles["Heading2"]))
    table_data = [["Время", "Критичность", "Источник", "Описание"]]
    for _, row in df.iterrows():
        table_data.append(
            [
                row["timestamp"].strftime("%d.%m.%Y %H:%M:%S"),
                row["severity"],
                row["source"],
                row["message"],
            ]
        )
    if len(table_data) == 1:
        table_data.append(["-", "-", "-", "Нет событий для отчёта"])

    table = Table(table_data, colWidths=[28 * mm, 24 * mm, 38 * mm, 88 * mm], repeatRows=1)
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("FONTSIZE", (0, 0), (-1, -1), 8.4),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.HexColor("#f3f4f6")]),
                ("LEADING", (0, 0), (-1, -1), 10),
            ]
        )
    )
    story.append(table)
    story.append(Spacer(1, 10))

    story.append(Paragraph("Источники событий", styles["Heading2"]))
    story.append(Paragraph(top_sources_text(df), styles["BodyText"]))
    story.append(Spacer(1, 8))

    story.append(Paragraph("Рекомендации", styles["Heading2"]))
    for rec in recs:
        story.append(Paragraph(f"• {rec}", styles["Small"]))

    doc.build(story)
    return buffer.getvalue()


# -----------------------------
# Sidebar controls
# -----------------------------
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
    st.caption("Учебный стенд для анализа цепочек атак и формирования отчётов.")

    scenario_title_to_id = {s.title: s.id for s in SCENARIOS}
    selected_title = st.selectbox(
        "Сценарий",
        options=list(scenario_title_to_id.keys()),
        index=list(scenario_title_to_id.keys()).index(scenario_obj.title),
    )
    selected_scenario_id = scenario_title_to_id[selected_title]

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
    st.caption("Подсказка: после запуска можно скачать PDF и CSV отчёты.")


# -----------------------------
# State transitions
# -----------------------------
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


# -----------------------------
# Main view
# -----------------------------
scenario_obj = scenario_by_id(st.session_state.selected_scenario)
all_df = build_dataframe(st.session_state.events)
filtered_df = apply_filters(all_df, severity_filter, source_filter)
metrics = metrics_for_df(filtered_df)
recs = analysis_recommendations(filtered_df)

st.title("Учебная SOC-песочница по кибербезопасности")
st.write(
    "Безопасный стенд для тренировки анализа событий, расследования инцидентов и формирования краткого отчёта по упражнению."
)

st.markdown('<div class="soft-card">', unsafe_allow_html=True)
left, right = st.columns([1.4, 1])
with left:
    st.subheader(scenario_obj.title)
    st.write(scenario_obj.brief)
    st.markdown("**Цели упражнения**")
    for goal in scenario_obj.goals:
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

st.subheader("Краткий анализ инцидента")
if filtered_df.empty:
    st.caption("Запустите сценарий, чтобы сформировать анализ.")
else:
    st.markdown(
        f"""
        **Сводка**

        - Всего событий: **{metrics['events']}**
        - Критических событий: **{metrics['critical']}**
        - Высоких событий: **{metrics['high']}**
        - Источников телеметрии: **{metrics['sources']}**
        - Временное окно: **{metrics['first'].strftime('%Y-%m-%d %H:%M:%S')} — {metrics['last'].strftime('%Y-%m-%d %H:%M:%S')}**
        """
    )
    st.markdown("**Рекомендации**")
    for item in recs:
        st.markdown(f"- {item}")

st.subheader("Отчёт по упражнению")
if filtered_df.empty:
    st.caption("Отчёт формируется по текущей выборке событий.")
else:
    csv_bytes = export_csv(filtered_df)
    try:
        pdf_bytes = export_pdf(filtered_df, scenario_obj, profile_label)
        pdf_error: Optional[str] = None
    except Exception as exc:
        pdf_bytes = None
        pdf_error = str(exc)

    c1, c2, c3 = st.columns([1, 1, 2])
    with c1:
        st.download_button(
            label="Скачать CSV",
            data=csv_bytes,
            file_name=f"soc_report_{scenario_obj.id}.csv",
            mime="text/csv",
            use_container_width=True,
        )
    with c2:
        if pdf_bytes is not None:
            st.download_button(
                label="Скачать PDF",
                data=pdf_bytes,
                file_name=f"soc_report_{scenario_obj.id}.pdf",
                mime="application/pdf",
                use_container_width=True,
            )
        else:
            st.button("Скачать PDF", disabled=True, use_container_width=True)
    with c3:
        st.caption(
            "В PDF включены сводка, хронология, статистика по источникам и рекомендации. Для русского текста в PDF нужен файл DejaVuSans.ttf рядом с app.py или в системных шрифтах."
        )
        if pdf_error:
            st.warning(pdf_error)

st.caption(
    "Совет: меняйте профиль атак, запускайте сценарий повторно и сравнивайте, как меняется лента событий."
)
