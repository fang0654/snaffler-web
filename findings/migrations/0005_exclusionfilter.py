import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("findings", "0004_finding_plugin_name"),
    ]

    operations = [
        migrations.CreateModel(
            name="ExclusionFilter",
            fields=[
                (
                    "id",
                    models.BigAutoField(
                        auto_created=True,
                        primary_key=True,
                        serialize=False,
                        verbose_name="ID",
                    ),
                ),
                ("substring", models.TextField()),
                ("created_at", models.DateTimeField(auto_now_add=True)),
                (
                    "source",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="exclusion_filters",
                        to="findings.source",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="exclusionfilter",
            constraint=models.UniqueConstraint(
                fields=("source", "substring"),
                name="findings_exclusionfilter_source_substring_uniq",
            ),
        ),
    ]
