import copy
from pages.page import Page
from widgets import Label
from PIL import ImageFont

class ListDetailPage(Page):
    def __init__(self, display, header, elements):
        self.detail_header = header
        self.detail_elements = elements
        self.copied_elements = [copy.copy(el) for el in elements]
        super().__init__(display)
        
    def body(self):
        header_label = Label(50, 10, self.detail_header, color="blue")
        header_label.font = ImageFont.truetype("Font/Font02.ttf", 24)
        self.add_element(header_label)
        y = 50
        for el in self.copied_elements:
            el.x = 50
            el.y = y
            el.font = ImageFont.truetype("Font/Font02.ttf", 24)
            self.add_element(el)
            y += el.height + 10

    def cleanup_copies(self):
        self.copied_elements.clear()