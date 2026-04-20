from django import template

register = template.Library()


@register.simple_tag
def sort_query(request, column: str) -> str:
    """Preserve filters; toggle order when sorting the same column."""
    q = request.GET.copy()
    q.pop("page", None)
    cur = q.get("sort", "occurred_at")
    ord_ = q.get("order", "desc")
    if cur == column:
        q["order"] = "asc" if ord_ == "desc" else "desc"
    else:
        q["order"] = "desc"
    q["sort"] = column
    return q.urlencode()
