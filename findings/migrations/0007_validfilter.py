import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("findings", "0006_finding_is_valid"),
    ]

    operations = [
        migrations.CreateModel(
            name="ValidFilter",
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
                        related_name="valid_filters",
                        to="findings.source",
                    ),
                ),
            ],
            options={
                "ordering": ["created_at"],
            },
        ),
        migrations.AddConstraint(
            model_name="validfilter",
            constraint=models.UniqueConstraint(
                fields=("source", "substring"),
                name="findings_validfilter_source_substring_uniq",
            ),
        ),
    ]
