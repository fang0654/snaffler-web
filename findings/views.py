from __future__ import annotations

from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpRequest, HttpResponseRedirect
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse

from .models import Finding, Source
from .services import import_snaffler_upload
from .smb_parse import parse_smb_from_file_uri

# Multiselect option value for rows with empty plugin_name or smb_host
_EMPTY_MULTI = "__empty__"


def _filter_query(request: HttpRequest) -> str:
    q = request.GET.copy()
    q.pop("page", None)
    return q.urlencode()


def _apply_multiselect_in(qs, field: str, selected: list[str]):
    """Filter qs where field is in selected non-empty values OR empty if sentinel selected."""
    if not selected:
        return qs
    rest = [v for v in selected if v != _EMPTY_MULTI]
    inc_empty = _EMPTY_MULTI in selected
    q = Q()
    if rest:
        q |= Q(**{f"{field}__in": rest})
    if inc_empty:
        q |= Q(**{field: ""})
    return qs.filter(q)


def home(request: HttpRequest):
    if request.method == "POST":
        f = request.FILES.get("file")
        if not f:
            return render(
                request,
                "findings/home.html",
                {"sources": Source.objects.all(), "error": "Choose a file to upload."},
            )
        try:
            source = import_snaffler_upload(f)
        except ValueError as e:
            return render(
                request,
                "findings/home.html",
                {"sources": Source.objects.all(), "error": str(e)},
            )
        return HttpResponseRedirect(
            reverse("findings:source_detail", args=[source.pk])
        )

    return render(
        request,
        "findings/home.html",
        {"sources": Source.objects.all()},
    )


def source_detail(request: HttpRequest, pk: int):
    source = get_object_or_404(Source, pk=pk)
    qs = source.findings.all()

    kind = request.GET.get("kind")
    if kind:
        qs = qs.filter(kind=kind)

    severity = request.GET.get("severity")
    if severity:
        qs = qs.filter(severity=severity)

    q = request.GET.get("q", "").strip()
    if q:
        qs = qs.filter(finding__icontains=q)

    uri_q = request.GET.get("uri_q", "").strip()
    if uri_q:
        qs = qs.filter(uri_search__icontains=uri_q)

    selected_plugins = request.GET.getlist("plugins")
    qs = _apply_multiselect_in(qs, "plugin_name", selected_plugins)

    selected_hosts = request.GET.getlist("hosts")
    qs = _apply_multiselect_in(qs, "smb_host", selected_hosts)

    sort = request.GET.get("sort", "smb_host")
    order = request.GET.get("order", "asc")
    allowed = {
        "occurred_at",
        "kind",
        "severity",
        "plugin_name",
        "smb_host",
        "smb_share",
        "finding",
    }
    if sort not in allowed:
        sort = "smb_host"
    desc = order != "asc"
    prefix = "-" if desc else ""
    if sort == "smb_host":
        qs = qs.order_by(f"{prefix}smb_host", f"{prefix}smb_share", f"{prefix}occurred_at")
    elif sort == "smb_share":
        qs = qs.order_by(f"{prefix}smb_share", f"{prefix}smb_host", f"{prefix}occurred_at")
    else:
        qs = qs.order_by(f"{prefix}{sort}")

    try:
        per_page = int(request.GET.get("per_page", "50"))
    except ValueError:
        per_page = 50
    if per_page not in (25, 50, 100, 200):
        per_page = 50

    paginator = Paginator(qs, per_page)
    page_obj = paginator.get_page(request.GET.get("page"))

    kinds = (
        source.findings.values_list("kind", flat=True)
        .distinct()
        .order_by("kind")
    )
    severities = (
        source.findings.exclude(severity="")
        .values_list("severity", flat=True)
        .distinct()
        .order_by("severity")
    )

    plugin_names = list(
        source.findings.exclude(plugin_name="")
        .values_list("plugin_name", flat=True)
        .distinct()
        .order_by("plugin_name")
    )
    plugin_rows_empty = source.findings.filter(plugin_name="").exists()
    plugin_options = [{"value": p, "label": p} for p in plugin_names]
    if plugin_rows_empty:
        plugin_options.append({"value": _EMPTY_MULTI, "label": "(no plugin)"})

    host_names = list(
        source.findings.exclude(smb_host="")
        .values_list("smb_host", flat=True)
        .distinct()
        .order_by("smb_host")
    )
    host_rows_empty = source.findings.filter(smb_host="").exists()
    host_options = [{"value": h, "label": h} for h in host_names]
    if host_rows_empty:
        host_options.append({"value": _EMPTY_MULTI, "label": "(no host)"})

    return render(
        request,
        "findings/source_detail.html",
        {
            "source": source,
            "page_obj": page_obj,
            "sort": sort,
            "order": "asc" if not desc else "desc",
            "filter_kind": kind or "",
            "filter_severity": severity or "",
            "filter_q": q,
            "filter_uri_q": uri_q,
            "per_page": per_page,
            "kinds": kinds,
            "severities": severities,
            "plugin_options": plugin_options,
            "host_options": host_options,
            "selected_plugins": selected_plugins,
            "selected_hosts": selected_hosts,
            "filter_query": _filter_query(request),
        },
    )


def smb_credentials(request: HttpRequest):
    if request.method == "POST":
        request.session["smb_domain"] = request.POST.get("domain", "").strip()
        request.session["smb_username"] = request.POST.get("username", "").strip()
        pw = request.POST.get("password", "")
        if pw:
            request.session["smb_password"] = pw
        request.session.modified = True
        nxt = request.POST.get("next") or reverse("findings:home")
        return redirect(nxt)
    return render(
        request,
        "findings/smb_credentials.html",
        {
            "domain": request.session.get("smb_domain", ""),
            "username": request.session.get("smb_username", ""),
            "password_saved": bool(request.session.get("smb_password")),
            "next": request.GET.get("next", ""),
        },
    )


def smb_terminal(request: HttpRequest):
    uri = request.GET.get("uri", "").strip()
    host = request.GET.get("host", "").strip()
    share = request.GET.get("share", "").strip()
    cd = request.GET.get("cd", "").strip()
    if uri:
        p = parse_smb_from_file_uri(uri)
        if p:
            host = p["host"]
            share = p["share"]
            cd = p["cd_path"]
    has_creds = bool(
        request.session.get("smb_username") and request.session.get("smb_password")
    )
    ws_params = {"host": host, "share": share, "cd": cd}
    return render(
        request,
        "findings/smb_terminal.html",
        {
            "host": host,
            "share": share,
            "cd": cd,
            "has_creds": has_creds,
            "ws_params": ws_params,
        },
    )
