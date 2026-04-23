from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("findings", "0005_exclusionfilter"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="is_valid",
            field=models.BooleanField(db_index=True, default=True),
        ),
    ]
