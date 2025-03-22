import copy
from pages.page import Page
from pages.focus_ignore_page import FocusIgnorePage
from widgets import Label
from PIL import ImageFont

class ListDetailPage(Page):
    def __init__(self, display, client, header, elements, is_ap_list=False):
        self.client = client
        self.detail_header = header
        self.detail_elements = elements
        self.copied_elements = [copy.copy(el) for el in elements]
        self.is_ap_list = is_ap_list
        if self.is_ap_list:
            self.aps = {}
        super().__init__(display)
        
    def body(self):
        header_label = Label(None, None, self.detail_header, color="Black")
        header_label.font = ImageFont.truetype("Font/Font02.ttf", 30)
        self.add_element(header_label)
        y = 50
        for el in self.copied_elements:
            el.x = 10
            el.y = y
            el.font = ImageFont.truetype("Font/Font02.ttf", 16)

            if self.is_ap_list:
                self.prepare_aps(el)

            self.add_element(el)
            y += el.height + 10

    def cleanup_copies(self):
        self.copied_elements.clear()

    def prepare_aps(self, el):
        el_name = el.text.split(" - ")[0]
        el_bssid = el.text.split(" - ")[1]
        self.aps[el_bssid] = el_name
        el.action = lambda: Page.open_page(FocusIgnorePage(self.display, self.client, name=el_name, bssid=el_bssid))