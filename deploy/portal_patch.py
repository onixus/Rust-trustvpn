"""Register the additive exchange integration once, including image upgrades."""
from pathlib import Path


def integrate(root):
    main = root / 'main.py'
    source = main.read_text(encoding='utf-8')
    anchor = 'app.include_router(client_router)'
    if source.count(anchor) != 1:
        raise RuntimeError('Portal router anchor mismatch')
    hook = 'rtrust_profiles.install(app)'
    if hook not in source:
        source = source.replace(anchor, 'from . import rtrust_profiles\n' + hook + '\n' + anchor)
    if source.count(hook) != 1:
        raise RuntimeError('Duplicate profile router registration')
    template = root / 'templates/base_client.html'
    html = template.read_text(encoding='utf-8')
    anchor = '<span class="sp"></span>'
    if html.count(anchor) != 1:
        raise RuntimeError('Portal navigation anchor mismatch')
    if 'href="/profiles"' not in html:
        html = html.replace(anchor, anchor + '\n  {% if request.cookies.get("user_token") %}<a href="/profiles">Обмен профилями</a>{% endif %}')
    # Validate both anchors before writing either file.
    main.write_text(source, encoding='utf-8')
    template.write_text(html, encoding='utf-8')


if __name__ == '__main__':
    integrate(Path('/app/app'))
    print('Applied profile API and navigation integration')
