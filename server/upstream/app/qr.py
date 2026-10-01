"""Отрисовка QR в SVG для встраивания прямо в страницу.

SVG, а не PNG: не нужен Pillow, картинка масштабируется без потерь и не требует
отдельного запроса к серверу (а значит, ссылка с кодом не оседает в логах доступа).
"""
import io

import qrcode
import qrcode.image.svg


def svg(data: str, box_size: int = 8, border: int = 2) -> str:
    """Возвращает разметку <svg> с QR-кодом для data."""
    qr = qrcode.QRCode(
        # M: до 15% повреждений — запас для съёмки с экрана под углом.
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(image_factory=qrcode.image.svg.SvgPathImage)
    buf = io.BytesIO()
    img.save(buf)
    return buf.getvalue().decode("utf-8")
