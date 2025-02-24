from widgets import Label, Button, ElementList, BatteryBar
from pages.page import Page
from pages.list_detail_page import ListDetailPage
from pages.green_page import GreenPage
from PIL import ImageFont

class MainMenu(Page):
    def body(self):
        self.batt_bar = BatteryBar(0, 0)

        self.title = Label(None, None, "Welcome!", color="green")
        self.title.font = ImageFont.truetype("Font/Font02.ttf", 24)
        
        self.btn_ok = Button(None, None, 100, 30, "OK", action=self.sample_action, bg_color="blue", text_color="white")
        
        self.text_lst = ElementList(None, None, header="Text Elements", text_color="black", spacing=1, clickable=True, action=self.list_pressed)
        for i in range(10):
            self.text_lst.add_element(Label(None, None, f"Text {i}", color="black"))

        self.button_lst = ElementList(None, None, header="Button Elements", text_color="black", spacing=1, clickable=True, action=self.list_pressed)
        self.button_lst.add_element(Button(None, None, 75, 20, "Button 1", action=self.sample_action, bg_color="red", text_color="black"))
        self.button_lst.add_element(Button(None, None, 75, 20, "Button 2", action=self.sample_action, bg_color="yellow", text_color="red"))
        self.button_lst.add_element(Button(None, None, 75, 20, "Button 3", action=self.sample_action, bg_color="green", text_color="pink"))
        
        self.add_element(self.batt_bar)
        self.add_element(self.title)
        self.add_element(self.btn_ok)
        self.add_element(self.text_lst)
        self.add_element(self.button_lst)

    def sample_action(self):
        new_page = GreenPage(self.display)
        Page.open_page(new_page)

    def list_pressed(self, elementlist):
        header_text = elementlist.header.text if elementlist.header else "Details"
        detail_elements = elementlist.elements[1:] if elementlist.header else elementlist.elements
        new_page = ListDetailPage(self.display, header_text, detail_elements)
        Page.open_page(new_page)