def string_to_hex_color(s):
    hex_value = int(s.encode("utf-8").hex(), 16)
    r = hex(hex_value % 256)[2:].zfill(2)
    g = hex((hex_value // 256) % 256)[2:].zfill(2)
    b = hex((hex_value // 65536) % 256)[2:].zfill(2)
    hex_color = "#{}{}{}".format(r.zfill(2), g.zfill(2), b.zfill(2))
    return hex_color


def lighten_hex_color(hex_color: str, amount: float):
    hex_color = hex_color.lstrip("#")
    rgb = tuple(int(hex_color[i : i + 2], 16) for i in (0, 2, 4))
    new_rgb = tuple(int(channel + (255 - channel) * amount) for channel in rgb)
    new_hex_color = "#{:02x}{:02x}{:02x}".format(*new_rgb)
    return new_hex_color
