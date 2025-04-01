import colorsys
import hashlib


def lighten_hex_color_for_light_mode(
    hex_color: str, min_lightness: float = 0.85
) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = [int(hex_color[i : i + 2], 16) / 255.0 for i in (0, 2, 4)]

    h, l, s = colorsys.rgb_to_hls(r, g, b)

    l = max(l, min_lightness)

    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))


def darken_hex_color_for_dark_mode(hex_color: str, max_lightness: float = 0.3) -> str:
    hex_color = hex_color.lstrip("#")
    r, g, b = [int(hex_color[i : i + 2], 16) / 255.0 for i in (0, 2, 4)]

    h, l, s = colorsys.rgb_to_hls(r, g, b)

    l = min(l, max_lightness)

    r, g, b = colorsys.hls_to_rgb(h, l, s)
    return "#{:02x}{:02x}{:02x}".format(int(r * 255), int(g * 255), int(b * 255))


def string_to_hex_color(s: str) -> str:
    hash_digest = hashlib.md5(s.encode("utf-8")).hexdigest()
    return f"#{hash_digest[:6]}"
