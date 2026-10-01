"""Apply only the additive exchange integration to the existing portal image."""
from pathlib import Path
p=Path('/app/app/main.py');s=p.read_text()
assert 'rtrust_profiles.install(app)' not in s
anchor='app.include_router(client_router)'
assert s.count(anchor)==1
s=s.replace(anchor,'from . import rtrust_profiles\nrtrust_profiles.install(app)\n'+anchor)
p.write_text(s)
p=Path('/app/app/templates/base_client.html');s=p.read_text()
anchor='<span class="sp"></span>'
assert s.count(anchor)==1
s=s.replace(anchor,anchor+'\n  {% if request.cookies.get("user_token") %}<a href="/profiles">Обмен профилями</a>{% endif %}')
p.write_text(s)
print('Applied profile API and navigation integration')
