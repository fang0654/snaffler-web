from __future__ import annotations

from django.core.paginator import Paginator
from django.db.models import Q
from django.http import HttpRequest, HttpResponseRedirect, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.views.decorators.http import require_POST

from .models import ExclusionFilter, Finding, Source, ValidFilter
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

    selected_include_valid_ids: list[int] = []
    for raw in request.GET.getlist("include_valid"):
        try:
            selected_include_valid_ids.append(int(raw))
        except ValueError:
            continue
    if selected_include_valid_ids:
        active_valid = list(
            ValidFilter.objects.filter(
                source=source, pk__in=selected_include_valid_ids
            )
        )
        if active_valid:
            qv = Q()
            for flt in active_valid:
                qv |= Q(finding__icontains=flt.substring)
            qs = qs.filter(qv)

    selected_exclude_ids: list[int] = []
    for raw in request.GET.getlist("exclude"):
        try:
            selected_exclude_ids.append(int(raw))
        except ValueError:
            continue
    if selected_exclude_ids:
        active_filters = ExclusionFilter.objects.filter(
            source=source, pk__in=selected_exclude_ids
        )
        for flt in active_filters:
            qs = qs.exclude(finding__icontains=flt.substring)

    sort = request.GET.get("sort", "smb_host")
    order = request.GET.get("order", "asc")
    allowed = {
        "id",
        "occurred_at",
        "kind",
        "severity",
        "is_valid",
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

    exclusion_filters = list(source.exclusion_filters.all())
    valid_filters = list(source.valid_filters.all())

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
            "exclusion_filters": exclusion_filters,
            "valid_filters": valid_filters,
            "selected_exclude_ids": selected_exclude_ids,
            "selected_include_valid_ids": selected_include_valid_ids,
            "filter_query": _filter_query(request),
        },
    )


@require_POST
def set_finding_is_valid(request: HttpRequest, pk: int, finding_pk: int):
    source = get_object_or_404(Source, pk=pk)
    finding = get_object_or_404(Finding, pk=finding_pk, source=source)
    finding.is_valid = request.POST.get("is_valid") == "1"
    finding.save(update_fields=["is_valid"])
    accept = request.META.get("HTTP_ACCEPT", "")
    if "application/json" in accept:
        return JsonResponse({"ok": True, "is_valid": finding.is_valid})
    nxt = (request.POST.get("next") or "").strip()
    if nxt.startswith("/") and not nxt.startswith("//"):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect(reverse("findings:source_detail", args=[source.pk]))


@require_POST
def create_exclusion_filter(request: HttpRequest, pk: int):
    source = get_object_or_404(Source, pk=pk)
    text = (request.POST.get("text") or "").strip()
    nxt = (request.POST.get("next") or "").strip()
    if text:
        ExclusionFilter.objects.get_or_create(source=source, substring=text)
    if nxt.startswith("/") and not nxt.startswith("//"):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect(reverse("findings:source_detail", args=[source.pk]))


@require_POST
def create_valid_filter(request: HttpRequest, pk: int):
    source = get_object_or_404(Source, pk=pk)
    text = (request.POST.get("text") or "").strip()
    nxt = (request.POST.get("next") or "").strip()
    if text:
        ValidFilter.objects.get_or_create(source=source, substring=text)
        Finding.objects.filter(
            source=source, finding__icontains=text
        ).update(is_valid=True)
    if nxt.startswith("/") and not nxt.startswith("//"):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect(reverse("findings:source_detail", args=[source.pk]))


@require_POST
def delete_exclusion_filter(request: HttpRequest, pk: int, filter_pk: int):
    source = get_object_or_404(Source, pk=pk)
    flt = get_object_or_404(ExclusionFilter, pk=filter_pk, source=source)
    flt.delete()
    nxt = (request.POST.get("next") or "").strip()
    if nxt.startswith("/") and not nxt.startswith("//"):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect(reverse("findings:source_detail", args=[source.pk]))


@require_POST
def delete_valid_filter(request: HttpRequest, pk: int, filter_pk: int):
    source = get_object_or_404(Source, pk=pk)
    flt = get_object_or_404(ValidFilter, pk=filter_pk, source=source)
    flt.delete()
    nxt = (request.POST.get("next") or "").strip()
    if nxt.startswith("/") and not nxt.startswith("//"):
        return HttpResponseRedirect(nxt)
    return HttpResponseRedirect(reverse("findings:source_detail", args=[source.pk]))


def smb_credentials(request: HttpRequest):
    if request.method == "POST":
        request.session["smb_domain"] = request.POST.get("domain", "").strip()
        request.session["smb_username"] = request.POST.get("username", "").strip()
        request.session["smb_use_dfs"] = request.POST.get("use_dfs") == "1"
        request.session["smb_smbclient_py"] = request.POST.get(
            "smbclient_py", ""
        ).strip()
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
            "use_dfs": bool(request.session.get("smb_use_dfs")),
            "smbclient_py": request.session.get("smb_smbclient_py", "") or "",
            "next": request.GET.get("next", ""),
        },
    )


def smb_terminal(request: HttpRequest):
    host = request.GET.get("host", "").strip()
    share = request.GET.get("share", "").strip()
    cd = request.GET.get("cd", "").strip()
    uri = request.GET.get("uri", "").strip()
    finding_pk_raw = request.GET.get("finding", "").strip()
    uri_index_raw = request.GET.get("uri_index", "").strip()

    finding_for_ws: int | None = None
    uri_index_for_ws: int | None = None
    if finding_pk_raw and uri_index_raw != "":
        try:
            row = Finding.objects.get(pk=int(finding_pk_raw))
            idx = int(uri_index_raw)
            uris = row.uris or []
            if 0 <= idx < len(uris):
                uri = uris[idx]
                finding_for_ws = row.pk
                uri_index_for_ws = idx
        except (ValueError, Finding.DoesNotExist):
            pass

    if uri:
        p = parse_smb_from_file_uri(uri)
        if p:
            host = p["host"]
            share = p["share"]
            cd = p["cd_path"]
    has_creds = bool(
        request.session.get("smb_username") and request.session.get("smb_password")
    )
    if (
        finding_for_ws is not None
        and uri_index_for_ws is not None
        and host
        and share
    ):
        ws_params = {"finding": finding_for_ws, "uri_index": uri_index_for_ws}
    else:
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
