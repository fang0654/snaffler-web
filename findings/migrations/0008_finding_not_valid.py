from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("findings", "0007_validfilter"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="not_valid",
            field=models.BooleanField(db_index=True, default=False),
        ),
    ]
