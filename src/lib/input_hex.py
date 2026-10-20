##########################################################################
# Required Notice: Copyright ETOILE401 SAS (http://www.lab401.com)
#
# Copyright (c) 2026: ETOILE401 SAS & https://github.com
#
#
# This software is licensed under the PolyForm Noncommercial License 1.0.0.
# You may not use this software for commercial purposes.
#
# A copy of the license is available at:
# https://polyformproject.org
#
# This entire header "Required Notice" must remain in place.
##########################################################################
"""Free-growing hex digit input widget.

Second line is indented to line up under the FIRST digit of line one.
Copyright (c) 2026: jareckib
"""

from lib._constants import SCREEN_W, CONTENT_Y0, CONTENT_H
from lib import resources

HEX_CHARS = '0123456789ABCDEF'

LABEL_COLOR = '#000000'
DIGIT_COLOR = '#0000FF'
DEFAULT_TEXT_COLOR = DIGIT_COLOR
CURSOR_COLOR = '#0000FF'
HINT_COLOR = '#606060'

TAG = '_hex_input'


class FreeHexInput(object):
    """Grows a hex value one digit at a time; wraps after per_line chars."""

    def __init__(self, canvas, label='', hint='', max_length=16,
                 per_line=8, x0=8, font_size=13, hint_font_size=10,
                 line_gap=20, y_offset=None, text_color=DEFAULT_TEXT_COLOR):
        self._canvas = canvas
        self._label = label
        self._hint = hint
        self._max_length = int(max_length)
        self._per_line = int(per_line)
        self._x0 = x0
        self._font = resources.get_font(font_size)
        self._hint_font = resources.get_font(hint_font_size)
        self._line_gap = line_gap
        default_y1 = CONTENT_Y0 + CONTENT_H // 2 - line_gap // 2
        self._y_offset = default_y1 if y_offset is None else int(y_offset)
        self._text_color = text_color
        self._digits = ['0']
        self._cursor = 0

        # Adjust the line splitting layouts based on the input boundaries
        if self._max_length == 8:
            self._per_line = 8
        elif self._max_length == 10:
            self._per_line = 10
        elif self._max_length == 16:
            self._per_line = 10

        # Defensive: never allow per_line to exceed max_length
        if self._per_line > self._max_length:
            self._per_line = self._max_length

    # -- public API ------------------------------------------------

    def setY(self, y):
        self._y_offset = int(y)

    def setLabel(self, label):
        self._label = label

    def setTextColor(self, color):
        self._text_color = color
        self._redraw()

    def show(self):
        self._redraw()

    def hide(self):
        self._canvas.delete(TAG)

    def rollUp(self):
        idx = HEX_CHARS.index(self._digits[self._cursor])
        self._digits[self._cursor] = HEX_CHARS[(idx + 1) % len(HEX_CHARS)]
        self._redraw()

    def rollDown(self):
        idx = HEX_CHARS.index(self._digits[self._cursor])
        self._digits[self._cursor] = HEX_CHARS[(idx - 1) % len(HEX_CHARS)]
        self._redraw()

    def moveLeft(self):
        if self._cursor > 0:
            self._cursor -= 1
            self._redraw()

    def moveRight(self):
        if self._cursor < len(self._digits) - 1:
            self._cursor += 1
        elif len(self._digits) < self._max_length:
            self._digits.append('0')
            self._cursor += 1
        self._redraw()

    def getValue(self):
        """Current hex digits as typed, e.g. '39' or '123456789ABCDEF0'."""
        return ''.join(self._digits)

    def length(self):
        return len(self._digits)

    # -- drawing -----------------------------------------------------

    def _redraw(self):
        canvas = self._canvas
        canvas.delete(TAG)

        row_top_y = self._y_offset
        row_bottom_y = row_top_y + self._line_gap

        digit_x0 = self._x0
        if self._label:
            item = canvas.create_text(
                self._x0, row_top_y, text=self._label, fill=LABEL_COLOR,
                font=self._font, anchor='w', tags=TAG,
            )
            bbox = canvas.bbox(item)
            if bbox:
                digit_x0 = bbox[2]

        x_row = [digit_x0, digit_x0]

        for i, ch in enumerate(self._digits):
            row = i // self._per_line
            if row > 1:
                row = 1

            y = row_top_y if row == 0 else row_bottom_y
            x = x_row[row]

            item = canvas.create_text(
                x, y, text=ch, fill=self._text_color,
                font=self._font, anchor='w', tags=TAG,
            )

            bbox = canvas.bbox(item)
            if bbox:
                x0, y0, x1, y1 = bbox
                if i == self._cursor:
                    canvas.create_line(
                        x0, y1 + 2, x1, y1 + 2,
                        fill=CURSOR_COLOR, width=2, tags=TAG,
                    )
                x_row[row] = x1
            else:
                x_row[row] = x + 10

        if self._hint:
            canvas.create_text(
                SCREEN_W // 2, CONTENT_Y0 + CONTENT_H - 2,
                text=self._hint, fill=HINT_COLOR,
                font=self._hint_font, anchor='s', tags=TAG,
            )