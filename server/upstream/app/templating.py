"""Единый экземпляр Jinja2Templates для всех роутеров."""
from fastapi.templating import Jinja2Templates

templates = Jinja2Templates(directory="app/templates")
